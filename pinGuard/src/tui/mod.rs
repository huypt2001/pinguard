use std::io;
use std::time::Duration;

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    Terminal,
};

pub mod app;
pub mod components;
pub mod events;
pub mod screens;
pub mod theme;

use app::{App, AppResult};
use events::{EventHandler, TuiEvent};

/// TUI ana giriş noktası
pub struct Tui<B: Backend> {
    terminal: Terminal<B>,
    pub events: EventHandler,
}

impl<B: Backend> Tui<B> {
    /// Yeni TUI instance oluştur
    pub fn new(terminal: Terminal<B>, events: EventHandler) -> Self {
        Self { terminal, events }
    }

    /// TUI'yi başlat
    pub fn init(&mut self) -> AppResult<()> {
        enable_raw_mode()?;
        execute!(io::stderr(), EnterAlternateScreen, EnableMouseCapture)?;
        self.terminal.hide_cursor()?;
        self.terminal.clear()?;
        Ok(())
    }

    /// Ana render loop
    pub fn draw(&mut self, app: &mut App) -> AppResult<()> {
        self.terminal.draw(|frame| app.render(frame))?;
        Ok(())
    }

    /// Terminal'i restore et
    pub fn exit(&mut self) -> AppResult<()> {
        disable_raw_mode()?;
        execute!(io::stderr(), LeaveAlternateScreen, DisableMouseCapture)?;
        self.terminal.show_cursor()?;
        Ok(())
    }
}

/// TUI uygulamasını çalıştır
pub async fn run_tui() -> AppResult<()> {
    // Terminal setup
    let backend = CrosstermBackend::new(io::stderr());
    let terminal = Terminal::new(backend)?;
    let events = EventHandler::new(Duration::from_millis(100));
    let mut tui = Tui::new(terminal, events);
    let mut app = App::new();

    // TUI'yi başlat
    tui.init()?;

    // Ana event loop
    loop {
        // UI'yi çiz
        tui.draw(&mut app)?;

        // Event'leri handle et
        match tui.events.next().await {
            Ok(TuiEvent::Tick) => app.tick(),
            Ok(TuiEvent::Key(key_event)) => {
                match key_event.code {
                    KeyCode::Char('q') | KeyCode::Char('Q') => {
                        if key_event.modifiers.contains(KeyModifiers::CONTROL) 
                            || app.should_quit() {
                            break;
                        }
                    }
                    _ => {}
                }
                app.handle_key_events(key_event).await?;
            }
            Ok(TuiEvent::Mouse(_)) => {}
            Ok(TuiEvent::Resize(width, height)) => {
                app.handle_resize(width, height);
            }
            Err(_) => break,
        }

        if app.should_quit() {
            break;
        }
    }

    // Cleanup
    tui.exit()?;
    Ok(())
}