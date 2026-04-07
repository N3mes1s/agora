use clap::Parser;
use serde_json::{Map, Value};
use std::io::{self, Read};

#[derive(Parser)]
#[command(name = "csv-to-json", about = "Convert CSV to JSON with column type detection")]
struct Cli {
    /// Input CSV file (reads from stdin if not provided)
    #[arg(short, long)]
    input: Option<std::path::PathBuf>,

    /// Output as JSON array (default) or newline-delimited JSON
    #[arg(long, default_value = "array")]
    format: Format,

    /// Skip type detection and treat all values as strings
    #[arg(long)]
    no_types: bool,
}

#[derive(Clone, clap::ValueEnum)]
enum Format {
    Array,
    Ndjson,
}

fn detect_type(value: &str) -> Value {
    if value.is_empty() {
        return Value::Null;
    }
    if value.eq_ignore_ascii_case("true") {
        return Value::Bool(true);
    }
    if value.eq_ignore_ascii_case("false") {
        return Value::Bool(false);
    }
    if value.eq_ignore_ascii_case("null") || value.eq_ignore_ascii_case("none") {
        return Value::Null;
    }
    if let Ok(i) = value.parse::<i64>() {
        return Value::Number(i.into());
    }
    if let Ok(f) = value.parse::<f64>() {
        if let Some(n) = serde_json::Number::from_f64(f) {
            return Value::Number(n);
        }
    }
    Value::String(value.to_string())
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let content = match &cli.input {
        Some(path) => std::fs::read_to_string(path)?,
        None => {
            let mut buf = String::new();
            io::stdin().read_to_string(&mut buf)?;
            buf
        }
    };

    let mut reader = csv::Reader::from_reader(content.as_bytes());
    let headers: Vec<String> = reader.headers()?.iter().map(|s| s.to_string()).collect();

    let records: Vec<Map<String, Value>> = reader
        .records()
        .map(|r| {
            let record = r?;
            let obj: Map<String, Value> = headers
                .iter()
                .zip(record.iter())
                .map(|(h, v)| {
                    let val = if cli.no_types {
                        Value::String(v.to_string())
                    } else {
                        detect_type(v)
                    };
                    (h.clone(), val)
                })
                .collect();
            Ok(obj)
        })
        .collect::<Result<_, csv::Error>>()?;

    match cli.format {
        Format::Array => {
            println!("{}", serde_json::to_string_pretty(&records)?);
        }
        Format::Ndjson => {
            for rec in &records {
                println!("{}", serde_json::to_string(rec)?);
            }
        }
    }

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_type_integer() {
        assert_eq!(detect_type("42"), Value::Number(42.into()));
        assert_eq!(detect_type("-7"), Value::Number((-7i64).into()));
    }

    #[test]
    fn test_detect_type_float() {
        match detect_type("3.14") {
            Value::Number(n) => {
                let f = n.as_f64().unwrap();
                assert!((f - 3.14).abs() < 1e-10);
            }
            other => panic!("expected Number, got {:?}", other),
        }
    }

    #[test]
    fn test_detect_type_bool() {
        assert_eq!(detect_type("true"), Value::Bool(true));
        assert_eq!(detect_type("False"), Value::Bool(false));
        assert_eq!(detect_type("TRUE"), Value::Bool(true));
    }

    #[test]
    fn test_detect_type_null() {
        assert_eq!(detect_type(""), Value::Null);
        assert_eq!(detect_type("null"), Value::Null);
        assert_eq!(detect_type("None"), Value::Null);
    }

    #[test]
    fn test_detect_type_string() {
        assert_eq!(detect_type("hello"), Value::String("hello".into()));
        assert_eq!(detect_type("2026-04-07"), Value::String("2026-04-07".into()));
    }

    #[test]
    fn test_roundtrip_csv() {
        let csv = "name,age,score,active\nAlice,30,9.5,true\nBob,25,8.0,false\nCarol,,7.1,null";
        let mut reader = csv::Reader::from_reader(csv.as_bytes());
        let headers: Vec<String> = reader.headers().unwrap().iter().map(|s| s.to_string()).collect();
        let records: Vec<Map<String, Value>> = reader
            .records()
            .map(|r| {
                let record = r.unwrap();
                headers.iter().zip(record.iter())
                    .map(|(h, v)| (h.clone(), detect_type(v)))
                    .collect()
            })
            .collect();

        assert_eq!(records.len(), 3);
        assert_eq!(records[0]["name"], Value::String("Alice".into()));
        assert_eq!(records[0]["age"], Value::Number(30.into()));
        assert_eq!(records[0]["active"], Value::Bool(true));
        assert_eq!(records[1]["active"], Value::Bool(false));
        assert_eq!(records[2]["age"], Value::Null);
        assert_eq!(records[2]["active"], Value::Null);
    }

    #[test]
    fn test_mixed_column_types() {
        let csv = "id,value\n1,foo\n2,42\n3,true";
        let mut reader = csv::Reader::from_reader(csv.as_bytes());
        let headers: Vec<String> = reader.headers().unwrap().iter().map(|s| s.to_string()).collect();
        let records: Vec<Map<String, Value>> = reader
            .records()
            .map(|r| {
                let record = r.unwrap();
                headers.iter().zip(record.iter())
                    .map(|(h, v)| (h.clone(), detect_type(v)))
                    .collect()
            })
            .collect();

        assert_eq!(records[0]["value"], Value::String("foo".into()));
        assert_eq!(records[1]["value"], Value::Number(42.into()));
        assert_eq!(records[2]["value"], Value::Bool(true));
    }
}
