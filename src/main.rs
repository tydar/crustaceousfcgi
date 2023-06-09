use std::io::prelude::*;
use std::net::Shutdown;
use std::os::unix::net::UnixStream;

mod fcgi;

fn main() -> std::io::Result<()> {
    // NEXT STEPS:
    // 1) implement serialization of FastCGI key-value pairs for _PARAMS
    // 2) get a minimal php-fpm dockerfile running
    // 3) attempt to manually send a minimal FastCGI request to that server
    // 4) spit out the response in stdout
    //
    // THEN: refactor so that a request struct is more abstracted; enum for body types BeginRequest
    // | EndRequest | KeyValue | Other
    // THEN: work on turning incoming HTTP requests into FastCGI requests

    let begin_body = fcgi::BeginRequest::new(fcgi::RoleType::Responder, 0, [0; 5]);
    let begin_bytes = begin_body.to_vec_u8().expect("Serialization failed");
    println!("begin bytes: {:?}", begin_bytes);
    let begin_rec = fcgi::Record::record_from_data(fcgi::RecordType::BeginRequest, begin_bytes, 0)
        .expect("Record creation failed");

    let mut kvs: Vec<fcgi::KeyValuePair> = Vec::new();
    kvs.push(fcgi::KeyValuePair::new(
        String::from("GATEWAY_INTERFACE"),
        String::from("CGI/1.1"),
    ));
    kvs.push(fcgi::KeyValuePair::new(
        String::from("SERVER_ADDR"),
        String::from("127.0.0.1"),
    ));
    kvs.push(fcgi::KeyValuePair::new(
        String::from("SERVER_PROTOCOL"),
        String::from("HTTP/2.0"),
    ));
    kvs.push(fcgi::KeyValuePair::new(
        String::from("SERVER_SOFTWARE"),
        String::from("Crustaceous/trunk"),
    ));
    kvs.push(fcgi::KeyValuePair::new(
        String::from("REQUEST_METHOD"),
        String::from("GET"),
    ));
    kvs.push(fcgi::KeyValuePair::new(
        String::from("REMOTE_ADDR"),
        String::from("127.0.0.1"),
    ));
    kvs.push(fcgi::KeyValuePair::new(
        String::from("SCRIPT_FILENAME"),
        String::from("/var/www/html/index.php"),
    ));
    kvs.push(fcgi::KeyValuePair::new(String::from(""), String::from("")));

    // Result type definitely allows a better way to do this
    let mut kv_records: Vec<fcgi::Record> = Vec::new();
    for kv in kvs {
        let data = kv.to_vec_u8().expect("KV serialization failed");
        let rec = fcgi::Record::record_from_data(fcgi::RecordType::Params, data, 0)
            .expect("Record creation failed");
        kv_records.push(rec);
    }

    let stdin_record = fcgi::Record::record_from_data(fcgi::RecordType::Stdin, vec![], 0)
        .expect("record creation failed");

    let mut out: Vec<u8> = Vec::new();

    out.extend(begin_rec.to_vec_u8());
    for kv in kv_records {
        out.extend(kv.to_vec_u8());
    }

    out.extend(stdin_record.to_vec_u8());

    let mut stream = UnixStream::connect("/var/run/php/php8.2-fpm-fpm-test.sock")?;
    stream.write_all(&out[..])?;

    let mut res_s = String::new();

    // Found this loop on StackOverflow.
    // https://stackoverflow.com/questions/74202534/why-am-i-not-getting-the-fcgi-end-request-record
    loop {
        let mut hbuf: [u8; 8] = [0; 8];
        stream.read_exact(&mut hbuf)?;

        if hbuf[1] != fcgi::RecordType::Stdout as u8 && hbuf[1] != fcgi::RecordType::Stderr as u8 {
            if hbuf[1] == fcgi::RecordType::EndRequest as u8 {
                println!("End Request record received");
            } else {
                println!("Request with type {:?} received", hbuf[1]);
            }
            break;
        }

        let size: usize = ((hbuf[4] as usize) << 8) | hbuf[5] as usize;
        let mut record_body: Vec<u8> = vec![0; size];
        stream.read_exact(&mut record_body)?;

        res_s.push_str(&String::from_utf8_lossy(&record_body));

        let padsz: usize = hbuf[6] as usize;
        let mut pad: Vec<u8> = vec![0; padsz];
        stream.read_exact(&mut pad);
    }

    println!("{}", res_s);

    Ok(())
}
