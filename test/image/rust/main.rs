use std::thread;
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

fn main() {
    let (tx, rx) = mpsc::channel();
    let rx = Arc::new(Mutex::new(rx));

    let producer = thread::spawn(move || {
        for i in 1..=10 {
            println!("producer: {}", i);
            tx.send(i).unwrap();
            thread::sleep(Duration::from_millis(250));
        }
    });

    let mut consumers = vec![];
    for id in 1..=4 {
        let rx_clone = Arc::clone(&rx);
        let consumer = thread::spawn(move || {
            loop {
                let result = rx_clone.lock().unwrap().recv();
                match result {
                    Ok(value) => {
                        println!("consumer {}: process {}", id, value);
                        thread::sleep(Duration::from_millis(100));
                    },
                    Err(_) => {
                        break;
                    }
                }
            }
        });
        consumers.push(consumer);
    }

    producer.join().unwrap();

    for consumer in consumers {
        consumer.join().unwrap();
    }
}
