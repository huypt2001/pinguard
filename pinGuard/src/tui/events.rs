use std::time::Duration;

use crossterm::event::{Event, KeyEvent, MouseEvent};
use tokio::sync::mpsc;
use tokio::time::{interval, Interval};

/// TUI event türleri
#[derive(Clone, Debug)]
pub enum TuiEvent {
    /// Tick event - düzenli aralıklarla güncelleme için
    Tick,
    /// Klavye input event'i
    Key(KeyEvent),
    /// Mouse event'i
    Mouse(MouseEvent),
    /// Terminal resize event'i
    Resize(u16, u16),
}

/// Event handler - crossterm event'lerini handle eder
pub struct EventHandler {
    sender: mpsc::UnboundedSender<TuiEvent>,
    receiver: mpsc::UnboundedReceiver<TuiEvent>,
    _handler: tokio::task::JoinHandle<()>,
}

impl EventHandler {
    /// Yeni event handler oluştur
    pub fn new(tick_rate: Duration) -> Self {
        let (sender, receiver) = mpsc::unbounded_channel();
        let _sender = sender.clone();

        let _handler = tokio::spawn(async move {
            let mut interval = interval(tick_rate);
            
            loop {
                let delay = interval.tick();
                let crossterm_event = crossterm::event::poll(Duration::from_millis(0));

                tokio::select! {
                    // Tick event
                    _ = delay => {
                        if _sender.send(TuiEvent::Tick).is_err() {
                            break;
                        }
                    }
                    // Crossterm event
                    result = async { crossterm_event } => {
                        match result {
                            Ok(true) => {
                                if let Ok(event) = crossterm::event::read() {
                                    let tui_event = match event {
                                        Event::Key(key) => TuiEvent::Key(key),
                                        Event::Mouse(mouse) => TuiEvent::Mouse(mouse),
                                        Event::Resize(width, height) => TuiEvent::Resize(width, height),
                                        _ => continue,
                                    };
                                    
                                    if _sender.send(tui_event).is_err() {
                                        break;
                                    }
                                }
                            }
                            Ok(false) => {
                                // No event available, continue
                                continue;
                            }
                            Err(_) => {
                                // Error reading event, break
                                break;
                            }
                        }
                    }
                }
            }
        });

        Self {
            sender,
            receiver,
            _handler,
        }
    }

    /// Bir sonraki event'i al
    pub async fn next(&mut self) -> Result<TuiEvent, Box<dyn std::error::Error + Send + Sync>> {
        self.receiver
            .recv()
            .await
            .ok_or_else(|| "Event channel closed".into())
    }
}