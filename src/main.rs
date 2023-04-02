use std::os::unix::net::UnixStream;
use std::net::Shutdown;
use std::io::prelude::*;

#[derive(Debug, Clone, Copy)]
enum FCGIRecordType {
    BeginRequest = 1,
    AbortRequest = 2,
    EndRequest = 3,
    Params = 4,
    Stdin = 5,
    Stdout = 6,
    Stderr = 7,
    Data = 8,
    GetValues = 9,
    GetValuesResult = 10,
    UnknownType = 11,
}

#[derive(Debug)]
struct FCGIHeader {
    version: u8,
    record_type: FCGIRecordType,
    request_id_hi: u8,
    request_id_lo: u8,
    content_length_hi: u8,
    content_length_lo: u8,
    padding_length: u8,
    reserved: u8,
}

#[derive(Debug)]
struct FCGIRecord {
    header: FCGIHeader,
    content_data: Vec<u8>,
    padding_data: Vec<u8>,
}

impl FCGIRecord {
    fn record_from_data(
        record_type: FCGIRecordType,
        content_data: Vec<u8>,
        padding_length: u8,
    ) -> Result<Self, String> {
        let content_length = content_data.len();

        if content_length > u16::MAX.into() {
            return Err(String::from("Content too long"));
        }

        if padding_length > u8::MAX {
            return Err(String::from("Padding too long"));
        }

        let content_length_hi = ((0xFF00 & content_length) >> 8).try_into();
        let content_length_lo = (0xFF & content_length).try_into();

        if content_length_hi.is_err() || content_length_lo.is_err() {
            return Err(String::from("Content length conversion failed"));
        }

        // NOTE: we are setting request ID to 1 for every request.
        //       this mirrors the behavior of nginx. Every request
        //       must have its own connection.
        let header = FCGIHeader {
            version: 1,
            record_type,
            request_id_hi: 0,
            request_id_lo: 1,
            content_length_hi: content_length_hi.unwrap(),
            content_length_lo: content_length_lo.unwrap(),
            padding_length,
            reserved: 0,
        };

        let padding_data: Vec<u8> = vec![0; padding_length.into()];

        Ok(Self {
            header,
            content_data,
            padding_data,
        })
    }

    fn to_vec_u8(&self) -> Vec<u8> {
        let mut output: Vec<u8> = Vec::new();

        let type_as_u8 = self.header.record_type as u8;

        output.push(self.header.version);
        output.push(type_as_u8);
        output.push(self.header.request_id_hi);
        output.push(self.header.request_id_lo);
        output.push(self.header.content_length_hi);
        output.push(self.header.content_length_lo);
        output.push(self.header.padding_length);
        output.push(self.header.reserved);
        output.extend(&self.content_data);
        output.extend(&self.padding_data);

        output
    }
}

// Special request body types

// https://www.mit.edu/~yandros/doc/specs/fcgi-spec.html#S3.4
struct FCGIKeyValuePair {
    name: String,
    value: String
}

impl FCGIKeyValuePair {
    fn to_vec_u8(&self) -> Result<Vec<u8>, String> {
        // TODO: don't need Vec for *_bytes
        //       but don't want to do array index
        //       math atm :)
        let name_size = self.name.len();
        let value_size = self.value.len();
        let mut name_size_bytes: Vec<u8> = Vec::new();
        let mut value_size_bytes: Vec<u8> = Vec::new();
        let mut output: Vec<u8> = Vec::new();

        // following code will panic if usize::BITS < 32
        let u32m_usize = usize::try_from(u32::MAX).unwrap();
        
        if name_size > u32m_usize || value_size > u32m_usize {
            return Err(String::from("Name or value size too large"));
        }


        for i in (0..4).rev() {
            let offset = 8*i;
            let mask: usize = 0xFF << offset;
            let name_byte = ((name_size & mask) >> offset).try_into();
            let value_byte = ((value_size & mask) >> offset).try_into();

            if value_byte.is_err() || name_byte.is_err() {
                return Err(String::from("Name or value size decomposition failed"))
            }

            name_size_bytes.push(name_byte.unwrap());
            value_size_bytes.push(value_byte.unwrap());
        }

        if name_size > u8::MAX.into() {
            for b in name_size_bytes {
                output.push(b);
            }
        } else {
            output.push(name_size_bytes[3]);
        }

        if value_size > u8::MAX.into() {
            for b in value_size_bytes {
                output.push(b);
            }
        } else {
            output.push(value_size_bytes[3]);
        }

        output.extend_from_slice(&self.name.as_bytes());
        output.extend_from_slice(&self.value.as_bytes());

        Ok(output)
    }
}

// https://www.mit.edu/~yandros/doc/specs/fcgi-spec.html#S5.1
#[derive(Debug, Clone, Copy)]
enum FCGIRoleType {
    Responder = 1,
    Authorizer = 2,
    Filter = 3
}

struct FCGIBeginRequest {
    role: FCGIRoleType,
    flags: u8,
    reserved: [u8; 5]
}

impl FCGIBeginRequest {
    fn to_vec_u8(&self) -> Result<Vec<u8>, String> {
        let mut output: Vec<u8> = Vec::new();
        let role_as_u16: u16 = self.role as u16;

        let role_hi = ((0xFF00 & role_as_u16) >> 8).try_into();
        let role_lo = (0xFF & role_as_u16).try_into();

        if role_hi.is_err() || role_lo.is_err() {
            return Err(String::from("Role serialization failed."));
        }

        output.push(role_hi.unwrap());
        output.push(role_lo.unwrap());

        output.push(self.flags);
        output.extend_from_slice(&self.reserved);

        Ok(output)
    }
}

fn main() -> std::io::Result<()> {
    // NEXT STEPS:
    // 1) implement serialization of FastCGI key-value pairs for FCGI_PARAMS
    // 2) get a minimal php-fpm dockerfile running
    // 3) attempt to manually send a minimal FastCGI request to that server
    // 4) spit out the response in stdout
    //
    // THEN: refactor so that a request struct is more abstracted; enum for body types BeginRequest
    // | EndRequest | KeyValue | Other
    // THEN: work on turning incoming HTTP requests into FastCGI requests
    
    let begin_body = FCGIBeginRequest {
        role: FCGIRoleType::Responder,
        flags: 0,
        reserved: [0; 5]
    };

    let begin_bytes = begin_body.to_vec_u8().expect("Serialization failed");
    let begin_rec = FCGIRecord::record_from_data(FCGIRecordType::BeginRequest, begin_bytes, 0).expect("Record creation failed");

    let mut kvs: Vec<FCGIKeyValuePair> = Vec::new();
    kvs.push(FCGIKeyValuePair {
        name: String::from("GATEWAY_INTERFACE"),
        value: String::from("CGI/1.1")
    });
    kvs.push(FCGIKeyValuePair {
        name: String::from("SERVER_ADDR"),
        value: String::from("127.0.0.1")
    });
    kvs.push(FCGIKeyValuePair {
        name: String::from("SERVER_PORT"),
        value: String::from("80")
    });
    kvs.push(FCGIKeyValuePair {
        name: String::from("SERVER_PROTOCOL"),
        value: String::from("HTTP/2.0")
    });
    kvs.push(FCGIKeyValuePair {
        name: String::from("SERVER_SOFTWARE"),
        value: String::from("CrustaceousFCGI/trunk")
    });
    kvs.push(FCGIKeyValuePair {
        name: String::from("REQUEST_METHOD"),
        value: String::from("GET")
    });
    kvs.push(FCGIKeyValuePair {
        name: String::from("REMOTE_ADDR"),
        value: String::from("127.0.0.1")
    });
    kvs.push(FCGIKeyValuePair {
        name: String::from(""),
        value: String::from("")
    });
    kvs.push(FCGIKeyValuePair {
        name: String::from("SCRIPT_FILENAME"),
        value: String::from("/var/www/html/index.php")
    });

    // Result type definitely allows a better way to do this
    let mut kv_records: Vec<FCGIRecord> = Vec::new();
    for kv in kvs {
        let data = kv.to_vec_u8().expect("KV serialization failed");
        let rec = FCGIRecord::record_from_data(FCGIRecordType::Params, data, 0).expect("Record creation failed");
        kv_records.push(rec);
    }

    let stdin_record = FCGIRecord::record_from_data(FCGIRecordType::Stdin, vec![], 0).expect("record creation failed");

    let mut out: Vec<u8> = Vec::new();

    out.extend(begin_rec.to_vec_u8());
    for kv in kv_records {
        out.extend(kv.to_vec_u8());
    }

    out.extend(stdin_record.to_vec_u8());

    let mut stream = UnixStream::connect("/var/run/php/php8.2-fpm-fpm-test.sock")?;
    stream.write_all(&out[..])?;
    let mut response: Vec<u8> = Vec::new();
    stream.read_to_end(&mut response)?;
    stream.shutdown(Shutdown::Both).expect("Socket shutdown failed");

    // turn the response after the header into a string
    let res_s = match std::str::from_utf8(&response[8..]) {
        Ok(v) => v,
        Err(e) => panic!("Invalid UTF8: {}", e),
    };
    println!("{}", res_s);

    Ok(())
}
