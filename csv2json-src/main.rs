use clap::Parser;
use serde_json::{Map, Value};
use std::io::{self, Write};

#[derive(Parser)]
#[command(name = "csv2json", about = "Convert CSV to JSON with column type detection")]
struct Args {
    /// Input CSV file (default: stdin)
    #[arg(short, long)]
    input: Option<String>,

    /// Output JSON file (default: stdout)
    #[arg(short, long)]
    output: Option<String>,

    /// Pretty-print JSON output
    #[arg(short, long)]
    pretty: bool,

    /// CSV delimiter (default: comma)
    #[arg(short, long, default_value = ",")]
    delimiter: String,
}

#[derive(Debug, Clone, PartialEq)]
enum ColType {
    Integer,
    Float,
    Boolean,
    Null,
    String,
}

fn detect_type(s: &str) -> ColType {
    let trimmed = s.trim();
    if trimmed.is_empty()
        || trimmed.eq_ignore_ascii_case("null")
        || trimmed.eq_ignore_ascii_case("na")
    {
        return ColType::Null;
    }
    if trimmed.eq_ignore_ascii_case("true") || trimmed.eq_ignore_ascii_case("false") {
        return ColType::Boolean;
    }
    if trimmed.parse::<i64>().is_ok() {
        return ColType::Integer;
    }
    if trimmed.parse::<f64>().is_ok() {
        return ColType::Float;
    }
    ColType::String
}

/// Widen two types to their common supertype.
fn merge_type(a: &ColType, b: &ColType) -> ColType {
    match (a, b) {
        (x, y) if x == y => x.clone(),
        (ColType::Null, other) | (other, ColType::Null) => other.clone(),
        (ColType::Integer, ColType::Float) | (ColType::Float, ColType::Integer) => ColType::Float,
        _ => ColType::String,
    }
}

fn coerce(s: &str, col_type: &ColType) -> Value {
    let trimmed = s.trim();
    match col_type {
        ColType::Null => Value::Null,
        ColType::Boolean => Value::Bool(trimmed.eq_ignore_ascii_case("true")),
        ColType::Integer => trimmed
            .parse::<i64>()
            .map(Value::from)
            .unwrap_or(Value::Null),
        ColType::Float => trimmed
            .parse::<f64>()
            .map(Value::from)
            .unwrap_or(Value::Null),
        ColType::String => {
            if trimmed.is_empty()
                || trimmed.eq_ignore_ascii_case("null")
                || trimmed.eq_ignore_ascii_case("na")
            {
                Value::Null
            } else {
                Value::String(s.to_string())
            }
        }
    }
}

pub fn csv_to_json(reader: impl io::Read, delimiter: u8) -> Result<Vec<Value>, String> {
    let mut rdr = csv::ReaderBuilder::new()
        .delimiter(delimiter)
        .from_reader(reader);

    let headers: Vec<String> = rdr
        .headers()
        .map_err(|e| e.to_string())?
        .iter()
        .map(|s| s.to_string())
        .collect();

    let mut rows: Vec<Vec<String>> = Vec::new();
    for result in rdr.records() {
        let record = result.map_err(|e| e.to_string())?;
        rows.push(record.iter().map(|s| s.to_string()).collect());
    }

    // Infer column types from all rows
    let mut col_types: Vec<ColType> = vec![ColType::Null; headers.len()];
    for row in &rows {
        for (i, val) in row.iter().enumerate() {
            if i < col_types.len() {
                let detected = detect_type(val);
                col_types[i] = merge_type(&col_types[i], &detected);
            }
        }
    }
    // Any column that stayed Null (all empty) → String
    for ct in col_types.iter_mut() {
        if *ct == ColType::Null {
            *ct = ColType::String;
        }
    }

    let mut output = Vec::with_capacity(rows.len());
    for row in &rows {
        let mut obj = Map::new();
        for (i, header) in headers.iter().enumerate() {
            let val = row.get(i).map(|s| s.as_str()).unwrap_or("");
            obj.insert(header.clone(), coerce(val, &col_types[i]));
        }
        output.push(Value::Object(obj));
    }

    Ok(output)
}

fn main() {
    let args = Args::parse();

    let delimiter = {
        let d = args.delimiter.as_bytes();
        if d.len() != 1 {
            eprintln!("error: delimiter must be a single character");
            std::process::exit(1);
        }
        d[0]
    };

    let result = match &args.input {
        Some(path) => {
            let f = std::fs::File::open(path).unwrap_or_else(|e| {
                eprintln!("error: {e}");
                std::process::exit(1);
            });
            csv_to_json(f, delimiter)
        }
        None => {
            let stdin = io::stdin();
            csv_to_json(stdin.lock(), delimiter)
        }
    };

    let records = result.unwrap_or_else(|e| {
        eprintln!("error: {e}");
        std::process::exit(1);
    });

    let json = if args.pretty {
        serde_json::to_string_pretty(&records)
    } else {
        serde_json::to_string(&records)
    }
    .expect("serialization failed");

    match &args.output {
        Some(path) => {
            let mut f = std::fs::File::create(path).unwrap_or_else(|e| {
                eprintln!("error: {e}");
                std::process::exit(1);
            });
            writeln!(f, "{json}").expect("write failed");
        }
        None => println!("{json}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(csv: &str) -> Vec<Value> {
        csv_to_json(csv.as_bytes(), b',').expect("parse failed")
    }

    #[test]
    fn integers_detected() {
        let records = parse("id,count\n1,42\n2,7\n");
        assert_eq!(records[0]["id"], Value::from(1i64));
        assert_eq!(records[0]["count"], Value::from(42i64));
    }

    #[test]
    fn floats_detected() {
        let records = parse("x,y\n1.5,2.0\n3.14,0.0\n");
        assert_eq!(records[0]["x"], Value::from(1.5f64));
    }

    #[test]
    fn booleans_detected() {
        let records = parse("flag\ntrue\nfalse\n");
        assert_eq!(records[0]["flag"], Value::Bool(true));
        assert_eq!(records[1]["flag"], Value::Bool(false));
    }

    #[test]
    fn null_values() {
        let records = parse("name,val\nAlice,\nBob,null\n");
        assert_eq!(records[0]["val"], Value::Null);
        assert_eq!(records[1]["val"], Value::Null);
    }

    #[test]
    fn mixed_int_float_widens_to_float() {
        let records = parse("n\n1\n2.5\n3\n");
        assert_eq!(records[0]["n"], Value::from(1.0f64));
        assert_eq!(records[1]["n"], Value::from(2.5f64));
    }

    #[test]
    fn strings_stay_strings() {
        let records = parse("city\nParis\nLondon\n");
        assert_eq!(records[0]["city"], Value::String("Paris".into()));
    }

    #[test]
    fn custom_delimiter() {
        let records = csv_to_json("a;b\n1;2\n".as_bytes(), b';').expect("parse failed");
        assert_eq!(records[0]["a"], Value::from(1i64));
        assert_eq!(records[0]["b"], Value::from(2i64));
    }

    #[test]
    fn empty_csv_returns_empty() {
        let records = parse("col\n");
        assert!(records.is_empty());
    }

    #[test]
    fn bool_case_insensitive() {
        let records = parse("flag\nTRUE\nFalse\n");
        assert_eq!(records[0]["flag"], Value::Bool(true));
        assert_eq!(records[1]["flag"], Value::Bool(false));
    }

    #[test]
    fn na_treated_as_null() {
        let records = parse("x\n1\nNA\n3\n");
        assert_eq!(records[1]["x"], Value::Null);
    }
}
