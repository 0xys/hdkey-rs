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
    fn to_queriable(&self) -> TokenQueriable {
        TokenQueriable {
            token: *self,
            result: false
        }
    }
}

pub struct Bip32Tokenizer {
    pub tokens: Vec<Token>,
    pub position: usize,
}

impl Bip32Tokenizer {
    pub fn new() -> Self {
        Bip32Tokenizer {
            tokens: vec![Token::Start],
            position: 0
        }
    }

    /// bip32 path tokenizer
    pub fn tokenize(&mut self, path: &str) -> Result<(), Bip32TokenizeError> {
        if path.len() == 0 {
            return Err(Bip32TokenizeError::EmptyPath);
        }
        self.tokenize_next(path)?;
        Ok(())
    }

    fn tokenize_next(&mut self, path: &str) -> Result<(), Bip32TokenizeError> {
        let current = path.chars().nth(0);
        if current == None {
            return Ok(());
        }
    
        let next = path.chars().nth(1);
        let token = Self::try_validate_token(current, next, self.position)?;
        self.tokens.push(token);
        self.position += 1;

        //  recursive call
        self.tokenize_next(&path[1..])?;
        Ok(())
    }

    fn try_validate_token(current: Option<char>, next: Option<char>, position: usize) -> Result<Token, Bip32TokenizeError> {
        let current = Self::try_tokenize_single(current, position)?;
        let next = Self::try_tokenize_single(next, position)?;
        Self::validate_next(current, position, next)?;
        Ok(current)
    }
    
    fn try_tokenize_single(ch: Option<char>, position: usize) -> Result<Token, Bip32TokenizeError> {
        let token = match ch {
            Some(c) => match c {
                'm' => Token::M,
                '\'' => Token::H,
                '/' => Token::Slash,
                '0'|'1'|'2'|'3'|'4'|'5'|'6'|'7'|'8'|'9' => Token::Number(c.to_digit(10).unwrap()),
                _ => return Err(Bip32TokenizeError::UnparsableAt(position, c))
            },
            None => Token::End
        };
        Ok(token)
    }
    
    fn validate_next(current: Token, position: usize, next: Token) -> Result<(), Bip32TokenizeError> {
        match current {
            Token::Start => next.to_queriable()
                .or(Token::M)
                .try_result(position, "[m] is expected")?,
            Token::M => next.to_queriable()
                .or(Token::Slash)
                .or(Token::End)
                .try_result(position, "[/] is expected")?,
            Token::Slash =>  next.to_queriable()
                .or_numbers()
                .try_result(position, "[0-9] is expected")?,
            Token::H => next.to_queriable()
                .or(Token::Slash)
                .or(Token::End)
                .try_result(position, "[/] is expected")?,
            Token::Number(_) => next.to_queriable()
                .or(Token::Slash)
                .or_numbers()
                .or(Token::H)
                .or(Token::End)
                .try_result(position, "[/,0-9,'] are expected")?,
            Token::End => return Ok(())
        }
        Ok(())
    }
}


#[derive(Debug, Copy, Clone, Eq, PartialEq)]
struct TokenQueriable {
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





#[cfg(test)]
mod tests {
    #[test]
    fn test(){

    }
}