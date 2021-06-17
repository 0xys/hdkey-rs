use crate::tokenizer::bip32::error::{Bip32TokenizeError};
use crate::tokenizer::bip32::token::Token;
use crate::tokenizer::bip32::node::{Node, Stack};


pub struct Bip32Tokenizer {
    tokens: Vec<Token>,
    position: usize,
}

impl Bip32Tokenizer {
    pub fn new() -> Self {
        Bip32Tokenizer {
            tokens: vec![Token::Start],
            position: 0
        }
    }

    /// bip32 path tokenizer
    pub fn tokenize(&mut self, path: &str) -> Result<Vec<Node>, Bip32TokenizeError> {
        if path.len() == 0 {
            return Err(Bip32TokenizeError::EmptyPath);
        }
        self.tokenize_next(path)?;
        let result = self.nodify()?;
        Ok(result)
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

    fn nodify(&self) -> Result<Vec<Node>, Bip32TokenizeError> {
        let mut stack = Stack::new();
        let mut nodes: Vec<Node> = vec![];

        for token in self.tokens.iter() {
            let node: Option<Node> = match token {
                Token::Start => None,
                Token::M => None,
                Token::Slash => Self::on_slash(&mut stack),
                Token::Number(_) => Self::on_number(&mut stack, *token),
                Token::H => Self::on_h(&mut stack, *token),
                Token::End => Self::on_slash(&mut stack)
            };
            
            match node {
                None => continue,
                Some(n) => nodes.push(n)
            };
        }

        Ok(nodes)
    }

    fn on_slash(stack: &mut Stack) -> Option<Node> {
        if stack.peek() == None {
            return None
        }

        let mut accumulator = 0;
        let mut is_hardened = false;
        let mut current_digit = 1;
        loop {
            let top = stack.pop();
            let num = match top {
                None => break,
                Some(token) => match *token {
                    Token::H => {
                        is_hardened = true;
                        continue;
                    },
                    Token::Number(n) => n,
                    _ => 0
                }
            };
            accumulator += num * current_digit;
            current_digit = current_digit*10;
        }

        let node = Node {
            index: accumulator,
            hardened: is_hardened,
        };
        Some(node)
    }

    fn on_number(stack: &mut Stack, token: Token) -> Option<Node> {
        stack.push(Box::new(token));
        None
    }

    fn on_h(stack: &mut Stack, token: Token) -> Option<Node> {
        stack.push(Box::new(token));
        None
    }

    fn try_validate_token(current: Option<char>, next: Option<char>, current_position: usize) -> Result<Token, Bip32TokenizeError> {
        let current = Self::try_tokenize_single(current, current_position)?;
        let next = Self::try_tokenize_single(next, current_position + 1)?;
        Self::validate_next(current, next, current_position + 1)?;
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
    
    fn validate_next(current: Token, next: Token, next_position: usize) -> Result<(), Bip32TokenizeError> {
        match current {
            Token::Start => next.to_queriable()
                .or(Token::M)
                .try_result(next_position, "[m] is expected here.")?,
            Token::M => next.to_queriable()
                .or(Token::Slash)
                .or(Token::End)
                .try_result(next_position, "[/] is expected here.")?,
            Token::Slash =>  next.to_queriable()
                .or_numbers()
                .try_result(next_position, "[0-9] is expected here.")?,
            Token::H => next.to_queriable()
                .or(Token::Slash)
                .or(Token::End)
                .try_result(next_position, "[/] is expected here.")?,
            Token::Number(_) => next.to_queriable()
                .or(Token::Slash)
                .or_numbers()
                .or(Token::H)
                .or(Token::End)
                .try_result(next_position, "[/,0-9,'] are expected here.")?,
            Token::End => return Ok(())
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::tokenizer::bip32::tokenizer::Bip32Tokenizer;
    use crate::tokenizer::bip32::token::Token;
    use crate::tokenizer::bip32::error::Bip32TokenizeError;

    #[test]
    fn test_validate_next(){

        // Start
        let result = Bip32Tokenizer::validate_next(Token::Start, Token::M, 1);
        expect_ok(result);
        let result = Bip32Tokenizer::validate_next(Token::Start, Token::Start, 1);
        expect_err(result);
        let result = Bip32Tokenizer::validate_next(Token::Start, Token::Number(0), 1);
        expect_err(result);
        let result = Bip32Tokenizer::validate_next(Token::Start, Token::Slash, 1);
        expect_err(result);
        let result = Bip32Tokenizer::validate_next(Token::Start, Token::H, 1);
        expect_err(result);
        let result = Bip32Tokenizer::validate_next(Token::Start, Token::End, 1);
        expect_err(result);

        //  M
        let result = Bip32Tokenizer::validate_next(Token::M, Token::Slash, 1);
        expect_ok(result);
        let result = Bip32Tokenizer::validate_next(Token::M, Token::End, 1);
        expect_ok(result);
        let result = Bip32Tokenizer::validate_next(Token::M, Token::Number(0), 1);
        expect_err(result);
        let result = Bip32Tokenizer::validate_next(Token::M, Token::H, 1);
        expect_err(result);
        let result = Bip32Tokenizer::validate_next(Token::M, Token::Start, 1);
        expect_err(result);

        // Slash
        let result = Bip32Tokenizer::validate_next(Token::Slash, Token::Number(0), 1);
        expect_ok(result);
        let result = Bip32Tokenizer::validate_next(Token::Slash, Token::Number(1), 1);
        expect_ok(result);
        let result = Bip32Tokenizer::validate_next(Token::Slash, Token::Number(2), 1);
        expect_ok(result);
        let result = Bip32Tokenizer::validate_next(Token::Slash, Token::Number(3), 1);
        expect_ok(result);
        let result = Bip32Tokenizer::validate_next(Token::Slash, Token::Number(4), 1);
        expect_ok(result);
        let result = Bip32Tokenizer::validate_next(Token::Slash, Token::Number(5), 1);
        expect_ok(result);
        let result = Bip32Tokenizer::validate_next(Token::Slash, Token::Number(6), 1);
        expect_ok(result);
        let result = Bip32Tokenizer::validate_next(Token::Slash, Token::Number(7), 1);
        expect_ok(result);
        let result = Bip32Tokenizer::validate_next(Token::Slash, Token::Number(8), 1);
        expect_ok(result);
        let result = Bip32Tokenizer::validate_next(Token::Slash, Token::Number(9), 1);
        expect_ok(result);
        let result = Bip32Tokenizer::validate_next(Token::Slash, Token::Slash, 1);
        expect_err(result);
        let result = Bip32Tokenizer::validate_next(Token::Slash, Token::Start, 1);
        expect_err(result);
        let result = Bip32Tokenizer::validate_next(Token::Slash, Token::End, 1);
        expect_err(result);
        let result = Bip32Tokenizer::validate_next(Token::Slash, Token::H, 1);
        expect_err(result);

        // H
        let result = Bip32Tokenizer::validate_next(Token::H, Token::End, 1);
        expect_ok(result);
        let result = Bip32Tokenizer::validate_next(Token::H, Token::Slash, 1);
        expect_ok(result);
        let result = Bip32Tokenizer::validate_next(Token::H, Token::Number(2), 1);
        expect_err(result);
        let result = Bip32Tokenizer::validate_next(Token::H, Token::H, 1);
        expect_err(result);
        let result = Bip32Tokenizer::validate_next(Token::H, Token::Start, 1);
        expect_err(result);

        // Number
        let result = Bip32Tokenizer::validate_next(Token::Number(0), Token::Slash, 1);
        expect_ok(result);
        let result = Bip32Tokenizer::validate_next(Token::Number(0), Token::Number(0), 1);
        expect_ok(result);
        let result = Bip32Tokenizer::validate_next(Token::Number(0), Token::H, 1);
        expect_ok(result);
        let result = Bip32Tokenizer::validate_next(Token::Number(0), Token::End, 1);
        expect_ok(result);
        let result = Bip32Tokenizer::validate_next(Token::Number(0), Token::Start, 1);
        expect_err(result);

        // End
        let result = Bip32Tokenizer::validate_next(Token::End, Token::Slash, 1);
        expect_ok(result);
    }

    #[test]
    fn test_tokenize_single(){
        let result = Bip32Tokenizer::try_tokenize_single(None, 0);
        expect_token(result, Token::End);

        let result = Bip32Tokenizer::try_tokenize_single(Some('m'), 0);
        expect_token(result, Token::M);

        let result = Bip32Tokenizer::try_tokenize_single(Some('\''), 0);
        expect_token(result, Token::H);

        let result = Bip32Tokenizer::try_tokenize_single(Some('/'), 0);
        expect_token(result, Token::Slash);

        let result = Bip32Tokenizer::try_tokenize_single(Some('0'), 0);
        expect_token(result, Token::Number(0));
        let result = Bip32Tokenizer::try_tokenize_single(Some('1'), 0);
        expect_token(result, Token::Number(1));
        let result = Bip32Tokenizer::try_tokenize_single(Some('2'), 0);
        expect_token(result, Token::Number(2));
        let result = Bip32Tokenizer::try_tokenize_single(Some('3'), 0);
        expect_token(result, Token::Number(3));
        let result = Bip32Tokenizer::try_tokenize_single(Some('4'), 0);
        expect_token(result, Token::Number(4));
        let result = Bip32Tokenizer::try_tokenize_single(Some('5'), 0);
        expect_token(result, Token::Number(5));
        let result = Bip32Tokenizer::try_tokenize_single(Some('6'), 0);
        expect_token(result, Token::Number(6));
        let result = Bip32Tokenizer::try_tokenize_single(Some('7'), 0);
        expect_token(result, Token::Number(7));
        let result = Bip32Tokenizer::try_tokenize_single(Some('8'), 0);
        expect_token(result, Token::Number(8));
        let result = Bip32Tokenizer::try_tokenize_single(Some('9'), 0);
        expect_token(result, Token::Number(9));

        let result = Bip32Tokenizer::try_tokenize_single(Some('-'), 0);
        expect_token_err(result);
        let result = Bip32Tokenizer::try_tokenize_single(Some('M'), 0);
        expect_token_err(result);
        let result = Bip32Tokenizer::try_tokenize_single(Some('H'), 0);
        expect_token_err(result);
    }

    fn expect_token(result: Result<Token, Bip32TokenizeError>, t: Token){
        let ok = match result {
            Ok(token) => token == t,
            Err(_) => false,
        };
        assert_eq!(true, ok);
    }

    fn expect_token_err(result: Result<Token, Bip32TokenizeError>){
        let ok = match result {
            Ok(_) => 1,
            Err(_) => 0,
        };
        assert_eq!(0, ok);
    }

    fn expect_ok(result: Result<(), Bip32TokenizeError>){
        let ok = match result {
            Ok(_) => 1,
            Err(_) => 0,
        };
        assert_eq!(1, ok);
    }

    fn expect_err(result: Result<(), Bip32TokenizeError>){
        let ok = match result {
            Ok(_) => 1,
            Err(_) => 0,
        };
        assert_eq!(0, ok);
    }
}