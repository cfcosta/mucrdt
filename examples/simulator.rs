use crossterm::{
    cursor::{Hide, MoveTo, Show},
    execute,
    style::{Color, Print, SetBackgroundColor, SetForegroundColor},
    terminal::{size, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen},
};
use mucrdt::prelude::*;
use noise::{NoiseFn, Perlin};
use rand::{rngs::StdRng, seq::IteratorRandom, Rng, SeedableRng};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    error::Error,
    io::{self, Write},
    thread,
    time::{Duration, Instant},
};

const ACTOR_COUNT: usize = 5;
const PLAN_STEPS: usize = 1000;
const NOISE_SCALE: f64 = 0.1;
const DEFAULT_FRAME_RATE: u64 = 30; // Default frames per second

#[derive(Clone)]
enum Step {
    Create {
        actor: usize,
        parents: [Hash; 2],
    },
    Gossip {
        from: usize,
        to: usize,
        delay: Duration,
        message_hash: Hash,
    },
}

struct Actor {
    hashgraph: HashGraph<blake3::Hasher>,
    messages: HashMap<Hash, Vec<u8>>,
    received_messages: HashSet<Hash>,
    last_received: Option<Hash>,
    sequence_number: u64,
}

impl Actor {
    fn new() -> Self {
        Actor {
            hashgraph: HashGraph::new(),
            messages: HashMap::new(),
            received_messages: HashSet::new(),
            last_received: None,
            sequence_number: 0,
        }
    }

    fn create_event(&mut self, parents: [Hash; 2]) -> (Hash, Vec<u8>) {
        let sequence_number = self.sequence_number;
        self.sequence_number += 1;
        let key = format!(
            "{}:{}:{}:{}",
            self.hashgraph.root(),
            parents[0].to_hex(),
            parents[1].to_hex(),
            sequence_number
        );
        let value = format!("actor:{}:{}", self.sequence_number, self.hashgraph.root());
        let proof = self.hashgraph.proof().clone();
        self.hashgraph
            .insert(&key.as_bytes(), &value.as_bytes())
            .unwrap();
        let message_hash = Hash::digest::<blake3::Hasher>(&key.as_bytes());
        let message = proof.to_bytes();
        (message_hash, message)
    }

    fn receive_event(&mut self, message_hash: Hash, message: Vec<u8>) {
        self.messages.insert(message_hash, message);
        self.received_messages.insert(message_hash);
        self.last_received = Some(message_hash);
    }
}

struct Plan {
    steps: Vec<Step>,
}

#[derive(Clone, Debug)]
enum GraphEvent {
    New(usize, Hash),
    Gossip(usize, usize, Hash),
}

struct Node {
    actor: usize,
    hash: Hash,
    children: Vec<Hash>,
    gossip_from: Vec<usize>,
}

struct Graph {
    nodes: HashMap<Hash, Node>,
    roots: Vec<Hash>,
}

impl Graph {
    fn new() -> Self {
        Graph {
            nodes: HashMap::new(),
            roots: Vec::new(),
        }
    }

    fn add_node(&mut self, actor: usize, hash: Hash) {
        let node = Node {
            actor,
            hash,
            children: Vec::new(),
            gossip_from: Vec::new(),
        };

        if parents.is_empty() {
            self.roots.push(hash);
        } else {
            for parent in &parents {
                if let Some(parent_node) = self.nodes.get_mut(parent) {
                    parent_node.children.push(hash);
                }
            }
        }

        self.nodes.insert(hash, node);
    }

    fn add_gossip(&mut self, from: usize, to: usize, hash: Hash) {
        if let Some(node) = self.nodes.get_mut(&hash) {
            if !node.gossip_from.contains(&from) {
                node.gossip_from.push(from);
            }
        }
    }
}

fn node_label(actor: usize, hash: Hash) -> String {
    format!("A{}:{}", actor, &hash.to_hex()[..4])
}

fn main() -> Result<(), Box<dyn Error>> {
    let seed = 12345;
    let mut rng = StdRng::seed_from_u64(seed);
    let plan = generate_plan(&mut rng);
    let frame_rate = std::env::var("FRAME_RATE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_FRAME_RATE);

    // Set up the terminal
    execute!(
        io::stdout(),
        EnterAlternateScreen,
        Clear(ClearType::All),
        Hide
    )?;

    // Run the simulation
    let result = run_simulation(plan, &mut rng, frame_rate);

    // Clean up the terminal
    execute!(io::stdout(), Show, LeaveAlternateScreen)?;

    // Print any errors
    if let Err(e) = result {
        eprintln!("Simulation error: {}", e);
    }

    Ok(())
}

fn generate_plan(rng: &mut StdRng) -> Plan {
    let mut steps = Vec::with_capacity(PLAN_STEPS);
    let perlin = Perlin::new(rng.gen());

    for i in 0..PLAN_STEPS {
        let noise_value = perlin.get([i as f64 * NOISE_SCALE, 0.0]);
        let normalized_noise = (noise_value + 1.0) / 2.0;

        if normalized_noise < 0.3 {
            let actor = rng.gen_range(0..ACTOR_COUNT);
            let parents = [
                Hash::from_slice(&rng.gen::<[u8; 32]>()),
                Hash::from_slice(&rng.gen::<[u8; 32]>()),
            ];
            steps.push(Step::Create { actor, parents });

            let to = (0..ACTOR_COUNT)
                .filter(|&x| x != actor)
                .choose(rng)
                .unwrap_or(actor);
            let delay = Duration::from_millis((normalized_noise * 150.0 + 50.0) as u64);
            let message_hash = Hash::digest::<blake3::Hasher>(
                &format!("{}:{}:{}", actor, parents[0].to_hex(), parents[1].to_hex()).as_bytes(),
            );
            steps.push(Step::Gossip {
                from: actor,
                to,
                delay,
                message_hash,
            });
        }
    }

    Plan { steps }
}

fn run_simulation(plan: Plan, rng: &mut StdRng, frame_rate: u64) -> Result<(), Box<dyn Error>> {
    let mut graph = Graph::new();
    let mut actors: Vec<Actor> = (0..ACTOR_COUNT).map(|_| Actor::new()).collect();
    let mut event_queue: VecDeque<(Instant, GraphEvent)> = VecDeque::new();
    let start_time = Instant::now();

    for step in plan.steps {
        match step {
            Step::Create { actor, parents } => {
                let (message_hash, message) = actors[actor].create_event(parents);
                actors[actor].receive_event(message_hash, message.clone());
                event_queue.push_back((start_time, GraphEvent::New(actor, message_hash)));
            }
            Step::Gossip {
                from,
                to,
                delay,
                message_hash,
            } => {
                if !actors[to].received_messages.contains(&message_hash) {
                    if let Some(message) = actors[from].messages.get(&message_hash) {
                        let message = message.clone();
                        actors[to].receive_event(message_hash, message);
                        event_queue.push_back((
                            start_time + delay,
                            GraphEvent::Gossip(from, to, message_hash),
                        ));

                        let next_to = (0..ACTOR_COUNT)
                            .filter(|&x| x != to && x != from)
                            .choose(rng);
                        if let Some(next_to) = next_to {
                            let next_delay = Duration::from_millis(rng.gen_range(50..200));
                            event_queue.push_back((
                                start_time + delay + next_delay,
                                GraphEvent::Gossip(to, next_to, message_hash),
                            ));
                        }
                    }
                }
            }
        }
    }

    let update_interval = Duration::from_millis(1000 / frame_rate);
    let mut last_update = Instant::now();

    let (terminal_width, terminal_height) = size().map_err(|e| e.to_string())?;
    let mut front_buffer = vec![
        vec![(' ', Color::Reset, Color::Reset); terminal_width as usize];
        terminal_height as usize
    ];
    let mut back_buffer = vec![
        vec![(' ', Color::Reset, Color::Reset); terminal_width as usize];
        terminal_height as usize
    ];

    loop {
        let current_time = Instant::now();

        if event_queue.is_empty()
            && current_time.duration_since(start_time) >= Duration::from_secs(30)
        {
            break;
        }

        // Process events
        while let Some((event_time, event)) = event_queue.front() {
            if *event_time <= current_time {
                let event = event_queue.pop_front().unwrap().1;
                update_graph(&mut graph, event, &actors)?;
            } else {
                break;
            }
        }

        // Render frame if it's time
        if current_time.duration_since(last_update) >= update_interval {
            render_graph(&graph, &mut back_buffer);
            update_screen(&front_buffer, &back_buffer)?;
            std::mem::swap(&mut front_buffer, &mut back_buffer);
            last_update = current_time;
        }

        // Add a small delay to prevent excessive CPU usage
        thread::sleep(Duration::from_millis(10));
    }

    Ok(())
}

fn update_graph(
    graph: &mut Graph,
    event: GraphEvent,
    actors: &[Actor],
) -> Result<(), Box<dyn Error>> {
    match event {
        GraphEvent::New(actor, message_hash) => {
            graph.add_node(actor, message_hash);
        }
        GraphEvent::Gossip(from_actor, to_actor, message_hash) => {
            if !graph.nodes.contains_key(&message_hash) {
                graph.add_node(to_actor, message_hash);
            }

            graph.add_gossip(from_actor, to_actor, message_hash);
        }
    }
    Ok(())
}

fn render_graph(graph: &Graph, buffer: &mut Vec<Vec<(char, Color, Color)>>) {
    // Clear the buffer
    for row in buffer.iter_mut() {
        for cell in row.iter_mut() {
            *cell = (' ', Color::Reset, Color::Reset);
        }
    }

    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    for &root in &graph.roots {
        queue.push_back((root, 0, 0));
    }

    let actor_colors = [
        Color::Red,
        Color::Green,
        Color::Blue,
        Color::Yellow,
        Color::Magenta,
    ];

    while let Some((hash, x, y)) = queue.pop_front() {
        if visited.contains(&hash) || y >= buffer.len() || x >= buffer[0].len() {
            continue;
        }
        visited.insert(hash);

        if let Some(node) = graph.nodes.get(&hash) {
            let label = node_label(node.actor, node.hash);
            let color = actor_colors[node.actor % actor_colors.len()];

            // Draw node
            if y < buffer.len() && x < buffer[y].len() {
                buffer[y][x] = ('+', color, Color::Reset);
                for i in 1..label.len().min(buffer[y].len() - x - 1) {
                    buffer[y][x + i] = ('-', color, Color::Reset);
                }
                let size = label.len().min(buffer[y].len() - x - 1);
                buffer[y][x + size] = ('+', color, Color::Reset);
            }

            // Draw label
            for (i, c) in label.chars().enumerate() {
                if y < buffer.len() && x + 1 + i < buffer[y].len() {
                    buffer[y][x + 1 + i] = (c, color, Color::Reset);
                }
            }

            // Draw gossip information
            if !node.gossip_from.is_empty() {
                let gossip_info = format!("G:{}", node.gossip_from.len());
                for (i, c) in gossip_info.chars().enumerate() {
                    if y + 1 < buffer.len() && x + i < buffer[y + 1].len() {
                        buffer[y + 1][x + i] = (c, Color::Cyan, Color::Reset);
                    }
                }
            }

            for (i, child) in node.children.iter().enumerate() {
                let child_x = x + 4;
                let child_y = y + 2 * (i + 1);

                // Draw connection line
                if child_y - 1 < buffer.len() && x + 1 < buffer[child_y - 1].len() {
                    buffer[child_y - 1][x + 1] = ('|', Color::White, Color::Reset);
                }
                if child_y - 1 < buffer.len() && child_x - 1 < buffer[child_y - 1].len() {
                    for j in x + 2..child_x {
                        buffer[child_y - 1][j] = ('-', Color::White, Color::Reset);
                    }
                }

                queue.push_back((*child, child_x, child_y));
            }
        }
    }
}

fn update_screen(
    front: &Vec<Vec<(char, Color, Color)>>,
    back: &Vec<Vec<(char, Color, Color)>>,
) -> Result<(), Box<dyn Error>> {
    for (y, (front_row, back_row)) in front.iter().zip(back.iter()).enumerate() {
        for (x, (front_cell, back_cell)) in front_row.iter().zip(back_row.iter()).enumerate() {
            if front_cell != back_cell {
                execute!(
                    io::stdout(),
                    MoveTo(x as u16, y as u16),
                    SetForegroundColor(back_cell.1),
                    SetBackgroundColor(back_cell.2),
                    Print(back_cell.0)
                )?;
            }
        }
    }
    io::stdout().flush()?;
    Ok(())
}
