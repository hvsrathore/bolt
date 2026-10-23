/* zero-copy Bencode (BEP-0003) parser operating over borrowed byte slices */

use std::fmt;

/* errors that can occur during Bencode deserialization */
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum BencodeError {
    /* unexpected end of buffer while expecting more bytes */
    UnexpectedEof { expected: &'static str, offset: usize },
    /* encountered invalid leading byte when determining token type */
    InvalidLeadingByte { byte: u8, offset: usize },
    /* integer encoding violates format specifications (e.g. leading zeros, minus zero) */
    InvalidIntegerFormat { offset: usize },
    /* integer value exceeds 64-bit signed integer capacity */
    IntegerOverflow { offset: usize },
    /* byte string length header contains non-digit or exceeds memory capacity */
    InvalidStringLength { offset: usize },
    /* dictionary key is not a valid Bencode byte string */
    DictionaryKeyNotString { offset: usize },
    /* dictionary keys are not sorted in ascending lexicographical order */
    UnsortedDictionaryKeys { offset: usize },
    /* extra unparsed trailing bytes remain after root entity */
    TrailingGarbage { offset: usize },
    /* byte string could not be interpreted as valid UTF-8 text */
    Utf8Error { offset: usize },
}

impl fmt::Display for BencodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof { expected, offset } => {
                write!(f, "unexpected EOF at offset {offset}, expected {expected}")
            }
            Self::InvalidLeadingByte { byte, offset } => {
                write!(f, "invalid token byte 0x{byte:02x} ('{}') at offset {offset}", *byte as char)
            }
            Self::InvalidIntegerFormat { offset } => {
                write!(f, "invalid integer encoding at offset {offset}")
            }
            Self::IntegerOverflow { offset } => {
                write!(f, "integer overflow at offset {offset}")
            }
            Self::InvalidStringLength { offset } => {
                write!(f, "invalid string length prefix at offset {offset}")
            }
            Self::DictionaryKeyNotString { offset } => {
                write!(f, "dictionary key at offset {offset} is not a byte string")
            }
            Self::UnsortedDictionaryKeys { offset } => {
                write!(f, "dictionary keys at offset {offset} violate lexicographical order")
            }
            Self::TrailingGarbage { offset } => {
                write!(f, "trailing unparsed bytes detected starting at offset {offset}")
            }
            Self::Utf8Error { offset } => {
                write!(f, "invalid UTF-8 sequence at offset {offset}")
            }
        }
    }
}

impl std::error::Error for BencodeError {}

/* dictionary entry storing borrowed key, parsed value, and original raw byte slice */
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DictEntry<'a> {
    pub key: &'a [u8],
    pub value: BencodeValue<'a>,
    /* exact raw byte slice of the value in the source buffer */
    pub raw_value: &'a [u8],
}

/* zero-copy Bencode value holding references to source byte slice */
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum BencodeValue<'a> {
    ByteStr(&'a [u8]),
    Integer(i64),
    List(Vec<BencodeValue<'a>>),
    Dict(Vec<DictEntry<'a>>),
}

impl<'a> BencodeValue<'a> {
    /* borrow value as raw byte slice if it is a byte string */
    pub fn as_bytes(&self) -> Option<&'a [u8]> {
        match self {
            Self::ByteStr(bytes) => Some(*bytes),
            _ => None,
        }
    }

    /* interpret byte string value as UTF-8 string slice */
    pub fn as_str(&self) -> Option<&'a str> {
        self.as_bytes().and_then(|bytes| std::str::from_utf8(bytes).ok())
    }

    /* extract 64-bit signed integer value */
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Integer(n) => Some(*n),
            _ => None,
        }
    }

    /* borrow value as a list slice */
    pub fn as_list(&self) -> Option<&[BencodeValue<'a>]> {
        match self {
            Self::List(list) => Some(list.as_slice()),
            _ => None,
        }
    }

    /* borrow value as dictionary entries */
    pub fn as_dict(&self) -> Option<&[DictEntry<'a>]> {
        match self {
            Self::Dict(entries) => Some(entries.as_slice()),
            _ => None,
        }
    }

    /* lookup child value by byte string key within dictionary */
    pub fn dict_get(&self, key: &[u8]) -> Option<&BencodeValue<'a>> {
        self.as_dict().and_then(|entries| {
            entries.iter().find(|entry| entry.key == key).map(|entry| &entry.value)
        })
    }

    /* extract raw unparsed byte slice for given dictionary key */
    pub fn dict_get_raw(&self, key: &[u8]) -> Option<&'a [u8]> {
        self.as_dict().and_then(|entries| {
            entries.iter().find(|entry| entry.key == key).map(|entry| entry.raw_value)
        })
    }

    /* lookup child value by UTF-8 string key within dictionary */
    pub fn dict_get_by_str(&self, key: &str) -> Option<&BencodeValue<'a>> {
        self.dict_get(key.as_bytes())
    }

    /* extract raw unparsed byte slice for given UTF-8 string key */
    pub fn dict_get_raw_by_str(&self, key: &str) -> Option<&'a [u8]> {
        self.dict_get_raw(key.as_bytes())
    }
}

/* stateful recursive-descent parser tracking byte offset in input slice */
pub struct BencodeParser<'a> {
    input: &'a [u8],
    cursor: usize,
    strict_sort: bool,
}

impl<'a> BencodeParser<'a> {
    /* instantiate parser over borrowed byte slice */
    pub fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            cursor: 0,
            strict_sort: false,
        }
    }

    /* configure whether dictionary keys must strictly adhere to lexicographical sorting */
    pub fn with_strict_sort(mut self, strict: bool) -> Self {
        self.strict_sort = strict;
        self
    }

    /* check if unconsumed bytes remain */
    pub fn has_remaining(&self) -> bool {
        self.cursor < self.input.len()
    }

    /* return slice of unconsumed bytes */
    pub fn remaining_slice(&self) -> &'a [u8] {
        &self.input[self.cursor..]
    }

    /* return current cursor position */
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /* peek at current byte without advancing cursor */
    fn peek_byte(&self) -> Result<u8, BencodeError> {
        if self.cursor >= self.input.len() {
            Err(BencodeError::UnexpectedEof {
                expected: "next token byte",
                offset: self.cursor,
            })
        } else {
            Ok(self.input[self.cursor])
        }
    }

    /* advance cursor and return consumed byte */
    fn next_byte(&mut self) -> Result<u8, BencodeError> {
        let b = self.peek_byte()?;
        self.cursor += 1;
        Ok(b)
    }

    /* parse top-level Bencode value and return both parsed tree and raw slice */
    pub fn parse_value_with_raw(&mut self) -> Result<(BencodeValue<'a>, &'a [u8]), BencodeError> {
        let start_pos = self.cursor;
        let value = self.parse_value()?;
        let end_pos = self.cursor;
        let raw_slice = &self.input[start_pos..end_pos];
        Ok((value, raw_slice))
    }

    /* parse single Bencode value based on leading character */
    pub fn parse_value(&mut self) -> Result<BencodeValue<'a>, BencodeError> {
        let leader = self.peek_byte()?;
        match leader {
            b'i' => self.parse_integer().map(BencodeValue::Integer),
            b'l' => self.parse_list().map(BencodeValue::List),
            b'd' => self.parse_dict().map(BencodeValue::Dict),
            b'0'..=b'9' => self.parse_byte_str().map(BencodeValue::ByteStr),
            other => Err(BencodeError::InvalidLeadingByte {
                byte: other,
                offset: self.cursor,
            }),
        }
    }

    /* parse integer token formatted as 'i<digits>e' */
    fn parse_integer(&mut self) -> Result<i64, BencodeError> {
        let start_pos = self.cursor;
        /* consume leading 'i' */
        let _ = self.next_byte()?;

        let mut is_negative = false;
        let mut digits_start = self.cursor;

        if self.peek_byte()? == b'-' {
            is_negative = true;
            self.cursor += 1;
            digits_start += 1;
        }

        let mut val: i64 = 0;
        let mut digit_count = 0;

        loop {
            let b = self.next_byte()?;
            if b == b'e' {
                break;
            }

            if !b.is_ascii_digit() {
                return Err(BencodeError::InvalidIntegerFormat { offset: self.cursor - 1 });
            }

            let digit = (b - b'0') as i64;

            /* check for 64-bit integer overflow before accumulating */
            if is_negative {
                val = val
                    .checked_mul(10)
                    .and_then(|v| v.checked_sub(digit))
                    .ok_or(BencodeError::IntegerOverflow { offset: start_pos })?;
            } else {
                val = val
                    .checked_mul(10)
                    .and_then(|v| v.checked_add(digit))
                    .ok_or(BencodeError::IntegerOverflow { offset: start_pos })?;
            }

            digit_count += 1;
        }

        /* enforce canonical integer rules: cannot be empty, no minus zero, no leading zeros */
        if digit_count == 0 {
            return Err(BencodeError::InvalidIntegerFormat { offset: start_pos });
        }

        let raw_digits = &self.input[digits_start..self.cursor - 1];
        if is_negative && val == 0 {
            /* negative zero 'i-0e' is forbidden by BEP-0003 */
            return Err(BencodeError::InvalidIntegerFormat { offset: start_pos });
        }

        if raw_digits.len() > 1 && raw_digits[0] == b'0' {
            /* leading zeros such as 'i03e' are forbidden */
            return Err(BencodeError::InvalidIntegerFormat { offset: start_pos });
        }

        Ok(val)
    }

    /* parse byte string token formatted as '<length>:<contents>' */
    fn parse_byte_str(&mut self) -> Result<&'a [u8], BencodeError> {
        let start_pos = self.cursor;
        let mut len: usize = 0;
        let mut digit_count = 0;

        loop {
            let b = self.next_byte()?;
            if b == b':' {
                break;
            }

            if !b.is_ascii_digit() {
                return Err(BencodeError::InvalidStringLength { offset: self.cursor - 1 });
            }

            let digit = (b - b'0') as usize;
            len = len
                .checked_mul(10)
                .and_then(|l| l.checked_add(digit))
                .ok_or(BencodeError::InvalidStringLength { offset: start_pos })?;

            digit_count += 1;
        }

        /* enforce string length rules: digits must be present, no leading zeros */
        if digit_count == 0 {
            return Err(BencodeError::InvalidStringLength { offset: start_pos });
        }

        let raw_len = &self.input[start_pos..self.cursor - 1];
        if raw_len.len() > 1 && raw_len[0] == b'0' {
            return Err(BencodeError::InvalidStringLength { offset: start_pos });
        }

        /* slice exact number of bytes directly from input without allocating heap memory */
        if self.cursor + len > self.input.len() {
            return Err(BencodeError::UnexpectedEof {
                expected: "byte string contents",
                offset: self.cursor,
            });
        }

        let slice = &self.input[self.cursor..self.cursor + len];
        self.cursor += len;
        Ok(slice)
    }

    /* parse list token formatted as 'l<contents>e' */
    fn parse_list(&mut self) -> Result<Vec<BencodeValue<'a>>, BencodeError> {
        /* consume leading 'l' */
        let _ = self.next_byte()?;
        let mut list = Vec::new();

        loop {
            let b = self.peek_byte()?;
            if b == b'e' {
                /* consume closing 'e' delimiter */
                let _ = self.next_byte()?;
                break;
            }
            list.push(self.parse_value()?);
        }

        Ok(list)
    }

    /* parse dictionary token formatted as 'd<key><value>...e' */
    fn parse_dict(&mut self) -> Result<Vec<DictEntry<'a>>, BencodeError> {
        let dict_start = self.cursor;
        /* consume leading 'd' */
        let _ = self.next_byte()?;

        let mut entries = Vec::new();
        let mut prev_key: Option<&'a [u8]> = None;

        loop {
            let b = self.peek_byte()?;
            if b == b'e' {
                /* consume closing 'e' delimiter */
                let _ = self.next_byte()?;
                break;
            }

            /* dictionary keys must always be byte strings */
            if !b.is_ascii_digit() {
                return Err(BencodeError::DictionaryKeyNotString { offset: self.cursor });
            }

            let key_offset = self.cursor;
            let key = self.parse_byte_str()?;

            /* verify ascending lexicographical key order if strict mode is active */
            if self.strict_sort
                && let Some(prev) = prev_key
                && prev >= key
            {
                return Err(BencodeError::UnsortedDictionaryKeys { offset: key_offset });
            }
            prev_key = Some(key);

            /* capture raw byte slice of the associated value */
            let val_start = self.cursor;
            let value = self.parse_value()?;
            let val_end = self.cursor;
            let raw_value = &self.input[val_start..val_end];

            entries.push(DictEntry {
                key,
                value,
                raw_value,
            });
        }

        /* suppress unused variable warning on dict_start */
        let _ = dict_start;
        Ok(entries)
    }
}

/* parse entire byte buffer into a BencodeValue, verifying no trailing bytes remain */
pub fn parse(input: &[u8]) -> Result<BencodeValue<'_>, BencodeError> {
    let mut parser = BencodeParser::new(input);
    let val = parser.parse_value()?;
    if parser.has_remaining() {
        return Err(BencodeError::TrailingGarbage { offset: parser.cursor() });
    }
    Ok(val)
}

/* parse entire byte buffer with strict lexicographical key ordering check */
pub fn parse_strict(input: &[u8]) -> Result<BencodeValue<'_>, BencodeError> {
    let mut parser = BencodeParser::new(input).with_strict_sort(true);
    let val = parser.parse_value()?;
    if parser.has_remaining() {
        return Err(BencodeError::TrailingGarbage { offset: parser.cursor() });
    }
    Ok(val)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_integer() {
        /* parse positive and negative integers and zero */
        assert_eq!(parse(b"i0e").unwrap(), BencodeValue::Integer(0));
        assert_eq!(parse(b"i42e").unwrap(), BencodeValue::Integer(42));
        assert_eq!(parse(b"i-123e").unwrap(), BencodeValue::Integer(-123));

        /* invalid integers */
        assert!(parse(b"i-0e").is_err());
        assert!(parse(b"i042e").is_err());
        assert!(parse(b"ie").is_err());
    }

    #[test]
    fn test_parse_byte_str() {
        /* parse zero-copy byte strings */
        assert_eq!(parse(b"4:spam").unwrap(), BencodeValue::ByteStr(b"spam"));
        assert_eq!(parse(b"0:").unwrap(), BencodeValue::ByteStr(b""));

        /* invalid strings */
        assert!(parse(b"04:spam").is_err());
        assert!(parse(b"5:spam").is_err());
    }

    #[test]
    fn test_parse_list() {
        /* parse homogeneous and heterogeneous lists */
        let data = b"l4:spami42ee";
        let parsed = parse(data).unwrap();
        let expected = BencodeValue::List(vec![
            BencodeValue::ByteStr(b"spam"),
            BencodeValue::Integer(42),
        ]);
        assert_eq!(parsed, expected);
    }

    #[test]
    fn test_parse_dict_and_extract_raw() {
        /* parse nested dictionary and retrieve raw byte slice of inner dictionary */
        let data = b"d4:infod6:lengthi1024e4:name8:test.txtee";
        let parsed = parse(data).unwrap();

        /* verify dictionary entries */
        let info_val = parsed.dict_get(b"info").expect("info key must exist");
        assert_eq!(info_val.dict_get(b"length").unwrap().as_i64(), Some(1024));
        assert_eq!(info_val.dict_get(b"name").unwrap().as_str(), Some("test.txt"));

        /* verify raw byte slice of info dictionary without re-serializing */
        let raw_info = parsed.dict_get_raw(b"info").expect("raw info slice must exist");
        assert_eq!(raw_info, b"d6:lengthi1024e4:name8:test.txte");
    }

    #[test]
    fn test_strict_dict_ordering() {
        /* valid lexicographical order */
        assert!(parse_strict(b"d1:a1:x1:b1:ye").is_ok());

        /* unsorted dictionary keys rejected in strict mode */
        assert!(parse_strict(b"d1:b1:y1:a1:xe").is_err());
    }
}
