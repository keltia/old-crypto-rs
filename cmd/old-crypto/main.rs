use std::io::{self, stdout};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
};
use old_crypto_rs::{
    Block as CipherBlock, ADFGVX, CaesarCipher, Chaocipher, Nihilist, NullCipher, PlayfairCipher,
    Solitaire, SquareCipher, StraddlingCheckerboard, Transposition, VicCipher, Wheatstone,
};

enum InputMode {
    Normal,
    Editing,
    SelectingCipher,
}

enum FocusedField {
    Cleartext,
    Key1,
    Key2,
    Key3,
    Key4,
}

struct App {
    input_mode: InputMode,
    focused_field: FocusedField,
    
    cleartext: String,
    key1: String,
    key2: String,
    key3: String,
    key4: String,
    result: String,
    
    ciphers: Vec<&'static str>,
    cipher_list_state: ListState,
    selected_cipher_index: usize,
}

impl App {
    fn new() -> App {
        let mut cipher_list_state = ListState::default();
        cipher_list_state.select(Some(0));
        App {
            input_mode: InputMode::Normal,
            focused_field: FocusedField::Cleartext,
            cleartext: String::new(),
            key1: String::new(),
            key2: String::new(),
            key3: String::new(),
            key4: String::new(),
            result: String::new(),
            ciphers: vec![
                "Caesar",
                "Playfair",
                "Chaocipher",
                "ADFGVX",
                "Solitaire",
                "Null",
                "Square",
                "Transposition",
                "Straddling",
                "Nihilist",
                "VIC",
                "Wheatstone",
                "Sigaba",
            ],
            cipher_list_state,
            selected_cipher_index: 0,
        }
    }

    fn run_cipher(&mut self) {
        let cipher_name = self.ciphers[self.selected_cipher_index];
        let src = self.cleartext.as_bytes();

        match cipher_name {
            "Caesar" => {
                if let Ok(shift) = self.key1.parse::<i32>() {
                    let cipher = CaesarCipher::new(shift);
                    let mut d = vec![0u8; src.len()];
                    cipher.encrypt(&mut d, src);
                    self.result = String::from_utf8_lossy(&d).to_string();
                } else {
                    self.result = "Invalid key (must be integer)".to_string();
                }
            }
            "Playfair" => {
                let cipher = PlayfairCipher::new(&self.key1);
                let mut d = vec![0u8; src.len() + 1]; // +1 for possible padding
                let n = cipher.encrypt(&mut d, src);
                self.result = String::from_utf8_lossy(&d[..n]).to_string();
            }
            "Chaocipher" => {
                match Chaocipher::new(&self.key1, &self.key2) {
                    Ok(cipher) => {
                        let mut d = vec![0u8; src.len()];
                        cipher.encrypt(&mut d, src);
                        self.result = String::from_utf8_lossy(&d).to_string();
                    }
                    Err(e) => {
                        self.result = format!("Error: {}", e);
                    }
                }
            }
            "ADFGVX" => {
                match ADFGVX::new(&self.key1, &self.key2) {
                    Ok(cipher) => {
                        let mut d = vec![0u8; src.len() * 4]; // ADFGVX doubles length then might pad
                        let n = cipher.encrypt(&mut d, src);
                        self.result = String::from_utf8_lossy(&d[..n]).to_string();
                    }
                    Err(e) => {
                        self.result = format!("Error: {}", e);
                    }
                }
            }
            "Solitaire" => {
                let cipher = Solitaire::new_with_passphrase(&self.key1);
                let mut d = vec![0u8; src.len() + 5]; // Padding to block size
                let n = cipher.encrypt(&mut d, src);
                self.result = String::from_utf8_lossy(&d[..n]).to_string();
            }
            "Null" => {
                let cipher = NullCipher::new();
                let mut d = vec![0u8; src.len()];
                cipher.encrypt(&mut d, src);
                self.result = String::from_utf8_lossy(&d).to_string();
            }
            "Square" => {
                match SquareCipher::new(&self.key1, &self.key2) {
                    Ok(cipher) => {
                        let mut d = vec![0u8; src.len() * 2];
                        let n = cipher.encrypt(&mut d, src);
                        self.result = String::from_utf8_lossy(&d[..n]).to_string();
                    }
                    Err(e) => self.result = format!("Error: {}", e),
                }
            }
            "Transposition" => {
                match Transposition::new(&self.key1) {
                    Ok(cipher) => {
                        let mut d = vec![0u8; src.len() + cipher.block_size()];
                        let n = cipher.encrypt(&mut d, src);
                        self.result = String::from_utf8_lossy(&d[..n]).to_string();
                    }
                    Err(e) => self.result = format!("Error: {}", e),
                }
            }
            "Straddling" => {
                match StraddlingCheckerboard::new(&self.key1, &self.key2) {
                    Ok(cipher) => {
                        let mut d = vec![0u8; src.len() * 3];
                        let n = cipher.encrypt(&mut d, src);
                        self.result = String::from_utf8_lossy(&d[..n]).to_string();
                    }
                    Err(e) => self.result = format!("Error: {}", e),
                }
            }
            "Nihilist" => {
                match Nihilist::new(&self.key1, &self.key2, &self.key3) {
                    Ok(cipher) => {
                        let mut d = vec![0u8; src.len() * 3];
                        let n = cipher.encrypt(&mut d, src);
                        self.result = String::from_utf8_lossy(&d[..n]).to_string();
                    }
                    Err(e) => self.result = format!("Error: {}", e),
                }
            }
            "VIC" => {
                match VicCipher::new(&self.key1, &self.key2, &self.key3, &self.key4) {
                    Ok(cipher) => {
                        let mut d = vec![0u8; src.len() * 4];
                        let n = cipher.encrypt(&mut d, src);
                        self.result = String::from_utf8_lossy(&d[..n]).to_string();
                    }
                    Err(e) => self.result = format!("Error: {}", e),
                }
            }
            "Wheatstone" => {
                let start = self.key1.as_bytes().first().cloned().unwrap_or(b'M');
                match Wheatstone::new(start, &self.key2, &self.key3) {
                    Ok(cipher) => {
                        let mut d = vec![0u8; src.len() * 2];
                        let n = cipher.encrypt(&mut d, src);
                        self.result = String::from_utf8_lossy(&d[..n]).to_string();
                    }
                    Err(e) => self.result = format!("Error: {}", e),
                }
            }
            "Sigaba" => {
                self.result = "Sigaba requires complex keying, not fully supported in TUI yet"
                    .to_string();
            }
            _ => self.result = "Not implemented in TUI yet".to_string(),
        }
    }
}

fn main() -> io::Result<()> {
    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;

    let mut app = App::new();
    let res = run_app(&mut terminal, &mut app);

    disable_raw_mode()?;
    stdout().execute(LeaveAlternateScreen)?;

    if let Err(err) = res {
        println!("{:?}", err);
    }

    Ok(())
}

fn run_app<B: Backend>(terminal: &mut Terminal<B>, app: &mut App) -> io::Result<()> 
where
    io::Error: From<B::Error>,
{
    loop {
        terminal.draw(|f| ui(f, app))?;

        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press {
                match app.input_mode {
                    InputMode::Normal => match key.code {
                        KeyCode::Char('q') => return Ok(()),
                        KeyCode::Char('e') => {
                            app.input_mode = InputMode::Editing;
                        }
                        KeyCode::Char('c') => {
                            app.input_mode = InputMode::SelectingCipher;
                        }
                        KeyCode::Tab => {
                            app.focused_field = match app.focused_field {
                                FocusedField::Cleartext => FocusedField::Key1,
                                FocusedField::Key1 => FocusedField::Key2,
                                FocusedField::Key2 => FocusedField::Key3,
                                FocusedField::Key3 => FocusedField::Key4,
                                FocusedField::Key4 => FocusedField::Cleartext,
                            };
                        }
                        KeyCode::Enter => {
                            app.run_cipher();
                        }
                        _ => {}
                    },
                    InputMode::SelectingCipher => match key.code {
                        KeyCode::Esc => {
                            app.input_mode = InputMode::Normal;
                        }
                        KeyCode::Up => {
                            let i = match app.cipher_list_state.selected() {
                                Some(i) => {
                                    if i == 0 {
                                        app.ciphers.len() - 1
                                    } else {
                                        i - 1
                                    }
                                }
                                None => 0,
                            };
                            app.cipher_list_state.select(Some(i));
                            app.selected_cipher_index = i;
                        }
                        KeyCode::Down => {
                            let i = match app.cipher_list_state.selected() {
                                Some(i) => {
                                    if i >= app.ciphers.len() - 1 {
                                        0
                                    } else {
                                        i + 1
                                    }
                                }
                                None => 0,
                            };
                            app.cipher_list_state.select(Some(i));
                            app.selected_cipher_index = i;
                        }
                        KeyCode::Enter => {
                            app.input_mode = InputMode::Normal;
                        }
                        _ => {}
                    },
                    InputMode::Editing => match key.code {
                        KeyCode::Esc => {
                            app.input_mode = InputMode::Normal;
                        }
                        KeyCode::Char(c) => {
                            match app.focused_field {
                                FocusedField::Cleartext => app.cleartext.push(c),
                                FocusedField::Key1 => app.key1.push(c),
                                FocusedField::Key2 => app.key2.push(c),
                                FocusedField::Key3 => app.key3.push(c),
                                FocusedField::Key4 => app.key4.push(c),
                            }
                        }
                        KeyCode::Backspace => {
                            match app.focused_field {
                                FocusedField::Cleartext => { app.cleartext.pop(); }
                                FocusedField::Key1 => { app.key1.pop(); }
                                FocusedField::Key2 => { app.key2.pop(); }
                                FocusedField::Key3 => { app.key3.pop(); }
                                FocusedField::Key4 => { app.key4.pop(); }
                            }
                        }
                        KeyCode::Enter => {
                            app.run_cipher();
                        }
                        _ => {}
                    },
                }
            }
        }
    }
}

fn ui(f: &mut Frame, app: &mut App) {
    let cipher_name = app.ciphers[app.selected_cipher_index];
    
    // Determine which key fields to show and their labels
    let key_configs = match cipher_name {
        "Caesar" => vec![("Shift (integer)", &app.key1)],
        "Playfair" => vec![("Key", &app.key1)],
        "Chaocipher" => vec![("Plain Alphabet", &app.key1), ("Cipher Alphabet", &app.key2)],
        "ADFGVX" => vec![("Square Key", &app.key1), ("Transposition Key", &app.key2)],
        "Solitaire" => vec![("Passphrase", &app.key1)],
        "Null" => vec![],
        "Square" => vec![("Key", &app.key1), ("Characters (6)", &app.key2)],
        "Transposition" => vec![("Key", &app.key1)],
        "Straddling" => vec![("Key", &app.key1), ("Blank Positions (2)", &app.key2)],
        "Nihilist" => vec![
            ("Checkerboard Key", &app.key1),
            ("Transposition Key", &app.key2),
            ("Blank Positions (2)", &app.key3),
        ],
        "VIC" => vec![
            ("Personal Code", &app.key1),
            ("Date/Index", &app.key2),
            ("Phrase", &app.key3),
            ("Key Message", &app.key4),
        ],
        "Wheatstone" => vec![
            ("Start Character", &app.key1),
            ("Plain Key", &app.key2),
            ("Cipher Key", &app.key3),
        ],
        "Sigaba" => vec![("Key (Not fully supported)", &app.key1)],
        _ => vec![("Key 1", &app.key1), ("Key 2", &app.key2)],
    };

    let mut constraints = vec![
        Constraint::Length(3), // Cipher
        Constraint::Length(3), // Cleartext
    ];
    for _ in 0..key_configs.len() {
        constraints.push(Constraint::Length(3));
    }
    constraints.push(Constraint::Min(3)); // Result
    constraints.push(Constraint::Length(3)); // Help

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(f.area());

    let (msg, style) = match app.input_mode {
        InputMode::Normal => (
            vec![
                "Normal Mode".into(),
                " | ".into(),
                "q".bold(),
                " to exit, ".into(),
                "e".bold(),
                " to edit, ".into(),
                "c".bold(),
                " to select cipher, ".into(),
                "TAB".bold(),
                " to switch focus, ".into(),
                "ENTER".bold(),
                " to encrypt".into(),
            ],
            Style::default().add_modifier(Modifier::RAPID_BLINK),
        ),
        InputMode::Editing => (
            vec![
                "Editing Mode".into(),
                " | ".into(),
                "ESC".bold(),
                " to stop editing, ".into(),
                "ENTER".bold(),
                " to encrypt".into(),
            ],
            Style::default(),
        ),
        InputMode::SelectingCipher => (
            vec![
                "Selecting Cipher".into(),
                " | ".into(),
                "UP/DOWN".bold(),
                " to move, ".into(),
                "ENTER/ESC".bold(),
                " to confirm".into(),
            ],
            Style::default(),
        ),
    };
    let help_message = Paragraph::new(Line::from(msg).style(style));
    f.render_widget(help_message, chunks[chunks.len() - 1]);

    let cipher_display = Paragraph::new(cipher_name)
        .block(Block::default().borders(Borders::ALL).title("Cipher (Press 'c' to change)"));
    f.render_widget(cipher_display, chunks[0]);

    let cleartext_input = Paragraph::new(app.cleartext.as_str())
        .style(match app.focused_field {
            FocusedField::Cleartext => Style::default().fg(Color::Yellow),
            _ => Style::default(),
        })
        .block(Block::default().borders(Borders::ALL).title("Cleartext"));
    f.render_widget(cleartext_input, chunks[1]);

    for (i, (label, value)) in key_configs.iter().enumerate() {
        let field_idx = i + 1;
        let is_focused = match app.focused_field {
            FocusedField::Key1 => field_idx == 1,
            FocusedField::Key2 => field_idx == 2,
            FocusedField::Key3 => field_idx == 3,
            FocusedField::Key4 => field_idx == 4,
            _ => false,
        };

        let input = Paragraph::new(value.as_str())
            .style(if is_focused {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default()
            })
            .block(Block::default().borders(Borders::ALL).title(*label));
        f.render_widget(input, chunks[i + 2]);
    }

    let result_display = Paragraph::new(app.result.as_str())
        .block(Block::default().borders(Borders::ALL).title("Result"))
        .wrap(Wrap { trim: true });
    f.render_widget(result_display, chunks[chunks.len() - 2]);

    if let InputMode::SelectingCipher = app.input_mode {
        let area = centered_rect(60, 40, f.area());
        f.render_widget(Clear, area);
        let items: Vec<ListItem> = app.ciphers.iter().map(|i| ListItem::new(*i)).collect();
        let list = List::new(items)
            .block(Block::default().title("Select Cipher").borders(Borders::ALL))
            .highlight_style(Style::default().add_modifier(Modifier::BOLD).fg(Color::Yellow))
            .highlight_symbol(">> ");
        f.render_stateful_widget(list, area, &mut app.cipher_list_state);
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
