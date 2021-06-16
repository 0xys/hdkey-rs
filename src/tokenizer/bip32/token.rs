use crate::tokenizer::bip32::error::{Bip32TokenizeError};


/// bip32 path unit
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Token {
    M,
    Slash,
    Number(u32),
    H,
    Start,
    End,
}

impl Token {
    pub fn to_queriable(&self) -> TokenQueriable {
        TokenQueriable {
            token: *self,
            result: false
        }
    }
}


#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct TokenQueriable {
    pub token: Token,
    pub result: bool
}

impl TokenQueriable {
    pub fn or(&self, token: Token) -> TokenQueriable {
        let result = match self.result {
            true => true,
            false => self.token == token,
        };
        TokenQueriable {
            token: self.token,
            result: result
        }
    }

    pub fn or_numbers(&self) -> TokenQueriable {
        let result = match self.result {
            true => true,
            false => match self.token {
                Token::Number(1) | Token::Number(2) | Token::Number(3)
                    | Token::Number(4) | Token::Number(5) | Token::Number(6)
                    | Token::Number(7) | Token::Number(8) | Token::Number(9)
                    | Token::Number(0) => true,
                _ => false
            },
        };
        TokenQueriable {
            token: self.token,
            result: result
        }
    }

    pub fn try_result(&self, position: usize, message: &str) -> Result<(), Bip32TokenizeError> {
        if self.result {
            return Ok(());
        }
        Err(Bip32TokenizeError::IncoherentAt(position, String::from(message)))
    }
}