use std::os::unix::net::UnixStream;
use std::io::Write;
use std::io::Read;
use std::io::Error;

#[derive(Debug, Clone, Copy)]
pub enum RecordType {
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
struct Header {
    version: u8,
    record_type: RecordType,
    request_id_hi: u8,
    request_id_lo: u8,
    content_length_hi: u8,
    content_length_lo: u8,
    padding_length: u8,
    reserved: u8,
}

#[derive(Debug)]
pub struct Record {
    header: Header,
    content_data: Vec<u8>,
    padding_data: Vec<u8>,
}

impl Record {
    pub fn record_from_data(
        record_type: RecordType,
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
        let header = Header {
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

    pub fn to_vec_u8(&self) -> Vec<u8> {
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
pub struct KeyValuePair {
    name: String,
    value: String,
}

impl KeyValuePair {
    pub fn new(name: String, value: String) -> KeyValuePair {
        KeyValuePair { name, value }
    }

    pub fn to_vec_u8(&self) -> Result<Vec<u8>, String> {
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
            let offset = 8 * i;
            let mask: usize = 0xFF << offset;
            let name_byte = ((name_size & mask) >> offset).try_into();
            let value_byte = ((value_size & mask) >> offset).try_into();

            if value_byte.is_err() || name_byte.is_err() {
                return Err(String::from("Name or value size decomposition failed"));
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
pub enum RoleType {
    Responder = 1,
    Authorizer = 2,
    Filter = 3,
}

pub struct BeginRequest {
    role: RoleType,
    flags: u8,
    reserved: [u8; 5],
}

impl BeginRequest {
    pub fn new(role: RoleType, flags: u8, reserved: [u8; 5]) -> BeginRequest {
        BeginRequest {
            role,
            flags,
            reserved,
        }
    }

    pub fn to_vec_u8(&self) -> Result<Vec<u8>, String> {
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


// Meta types

pub struct Server {
    params: Vec<KeyValuePair>,
    app: UnixStream,
}

impl Server {
    pub fn new(params_raw: Vec<(String, String)>, socket_addr: String) -> Server {
        let pair_to_kvp = |p: (String, String)| -> KeyValuePair {
            let (k, v) = p;
            KeyValuePair::new(k, v)
        };

        let params: Vec<KeyValuePair> = params_raw
                .iter().map(|x| pair_to_kvp(x.clone())).collect::<Vec<KeyValuePair>>();

        let stream = UnixStream::connect(socket_addr)
            .expect("Socket connection failed");

        Server {
            params: params,
            app: stream
        }
    }

    pub fn serialize_params(&self) -> Vec<u8> {
        let params_slice = &self.params[0..];
        let mut kv_records: Vec<Vec<u8>> = Vec::new();
        for kv in params_slice.iter() {
            let data = kv.to_vec_u8().expect("KV serialization failed");
            let rec = Record::record_from_data(RecordType::Params, data, 0)
                .expect("Record creation failed");
            kv_records.push(rec.to_vec_u8());
        }

        kv_records.concat()
    }

    pub fn send_request(&mut self, bytes: Vec<u8>) -> Result<(), Error> {
        self.app.write_all(&bytes[..])
    }

    pub fn consume_response_to_string(&mut self, response: &mut String) -> Result<(), Error> {
        // Found this loop on StackOverflow.
        // https://stackoverflow.com/questions/74202534/why-am-i-not-getting-the-fcgi-end-request-record
        loop {
            let mut hbuf: [u8; 8] = [0; 8];
            self.app.read_exact(&mut hbuf).expect("Failed on read_exact 1");

            if hbuf[1] != RecordType::Stdout as u8 && hbuf[1] != RecordType::Stderr as u8 {
                if hbuf[1] == RecordType::EndRequest as u8 {
                    println!("End Request record received");
                } else {
                    println!("Request with type {:?} received", hbuf[1]);
                }
                break;
            }

            let size: usize = ((hbuf[4] as usize) << 8) | hbuf[5] as usize;
            let mut record_body: Vec<u8> = vec![0; size];
            self.app.read_exact(&mut record_body).expect("Failed on read_exact 2");

            response.push_str(&String::from_utf8_lossy(&record_body));

            let padsz: usize = hbuf[6] as usize;
            let mut pad: Vec<u8> = vec![0; padsz];
            self.app.read_exact(&mut pad).expect("Failed on read_exact 3");
        }

        Ok(())
    }
}
