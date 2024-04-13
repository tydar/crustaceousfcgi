mod fcgi;

fn main() -> std::io::Result<()> {
    // NEXT STEPS:
    // 1) implement serialization of FastCGI key-value pairs for _PARAMS
    //      DOING THIS by implementing a fcgi::Server type
    // 2) get a minimal php-fpm dockerfile running
    // 3) attempt to manually send a minimal FastCGI request to that server
    // 4) spit out the response in stdout
    //
    // THEN: refactor so that a request struct is more abstracted; enum for body types BeginRequest
    // | EndRequest | KeyValue | Other
    // THEN: work on turning incoming HTTP requests into FastCGI requests

    let kvs_for_init: Vec<(String, String)> = vec![
        ("GATEWAY_INTERFACE".to_string(), "CGI/1.1".to_string()),
        ("SERVER_ADDR".to_string(), "127.0.0.1".to_string()),
        ("SERVER_PROTOCOL".to_string(), "HTTP/2.0".to_string()),
        ("SERVER_SOFTWARE".to_string(), "Crustaceous/trunk".to_string()),
        ("REQUEST_METHOD".to_string(), "GET".to_string()),
        ("REMOTE_ADDR".to_string(), "127.0.0.1".to_string()),
        ("SCRIPT_FILENAME".to_string(), "/var/www/html/index.php".to_string()),
    ];

    let mut server: fcgi::Server = fcgi::Server::new(
        kvs_for_init,
        "/var/run/php/php8.2-fpm.sock".to_string()
    );

    let begin_body = fcgi::BeginRequest::new(fcgi::RoleType::Responder, 0, [0; 5]);
    let begin_bytes = begin_body.to_vec_u8().expect("Serialization failed");
    println!("begin bytes: {:?}", begin_bytes);
    let begin_rec = fcgi::Record::record_from_data(fcgi::RecordType::BeginRequest, begin_bytes, 0)
        .expect("Record creation failed");

    // Result type definitely allows a better way to do this
    let kv_records: Vec<u8> = server.serialize_params();

    let stdin_record = fcgi::Record::record_from_data(fcgi::RecordType::Stdin, vec![], 0)
        .expect("record creation failed");

    let mut out: Vec<u8> = Vec::new();

    out.extend(begin_rec.to_vec_u8());

    out.extend(kv_records);

    out.extend(stdin_record.to_vec_u8());

    server.send_request(out)?;

    let mut res_s = String::new();


    server.consume_response_to_string(&mut res_s)?;

    println!("{}", res_s);

    Ok(())
}
