use crate::tokenizer::bip32::token::Token;

/// bip32 path node element
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Node {
    pub index: u32,
    pub hardened: bool
}

pub struct Stack {
    stack: Vec<Box<Token>>,
}

impl Stack {
    pub fn new() -> Self {
        Stack {
            stack: vec![]
        }
    }

    pub fn peek(&self) -> Option<&Box<Token>> {
        let top = self.stack.len() - 1;
        self.stack.get(top)
    }

    pub fn push(&mut self, token: Box<Token>){
        self.stack.push(token);
    }

    pub fn pop(&mut self) -> Option<Box<Token>> {
        if self.stack.len() == 0 {
            return None;
        }

        let top = self.stack.len() - 1;
        let top_element = self.stack.remove(top);
        Some(top_element)
    }
}