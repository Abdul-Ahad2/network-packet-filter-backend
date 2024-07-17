const express = require("express");
const multer = require("multer");
const PcapParser = require("pcap-parser");
const cors = require("cors");
const xlsx = require("xlsx");
const stream = require("stream");

const app = express();
const port = process.env.PORT || 3001;

app.use(cors());

// Multer storage configuration
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 }, // Limit file size to 10MB for example
});

let parsedData = [];
let packetDetails = [];

app.post("/upload", upload.single("pcapFile"), (req, res) => {
  if (!req.file) {
    return res.status(400).send("No file uploaded.");
  }

  // Convert the file buffer to a stream
  const bufferStream = new stream.PassThrough();
  bufferStream.end(req.file.buffer);
  const parser = PcapParser.parse(bufferStream);

  parsedData = [];
  packetDetails = [];
  let numberOfNetflixPackets = 0;
  let numberOfYouTubePackets = 0;
  let numberOfIpPackets = 0;
  let numberOfIpBytes = 0;
  let numberOfUdpPackets = 0;
  let startTime = null;
  let endTime = null;

  parser.on("packet", (packet) => {
    const data = packet.data;
    const timestamp = new Date(packet.header.timestampSeconds * 1000); // Assuming timestamp is in seconds
    const etherType = data.readUInt16BE(12);

    if (etherType === 0x0800) {
      // IPv4
      numberOfIpPackets++;
      numberOfIpBytes += data.length;

      const ipHeaderStart = 14;
      if (data.length < ipHeaderStart + 20) return; // Minimum length for IP header
      const ipHeaderLength = (data[ipHeaderStart] & 0x0f) * 4;
      if (data.length < ipHeaderStart + ipHeaderLength) return; // Validate IP header length
      const ipTotalLength = data.readUInt16BE(ipHeaderStart + 2);
      const protocol = data[ipHeaderStart + 9];

      if (!startTime || timestamp < startTime) startTime = timestamp;
      if (!endTime || timestamp > endTime) endTime = timestamp;

      const sourceIP = `${data[ipHeaderStart + 12]}.${
        data[ipHeaderStart + 13]
      }.${data[ipHeaderStart + 14]}.${data[ipHeaderStart + 15]}`;
      const destinationIP = `${data[ipHeaderStart + 16]}.${
        data[ipHeaderStart + 17]
      }.${data[ipHeaderStart + 18]}.${data[ipHeaderStart + 19]}`;

      if (protocol === 6) {
        // TCP
        const tcpHeaderStart = ipHeaderStart + ipHeaderLength;
        if (data.length < tcpHeaderStart + 20) return; // Minimum length for TCP header
        const tcpHeaderLength = ((data[tcpHeaderStart + 12] & 0xf0) >> 4) * 4;
        if (data.length < tcpHeaderStart + tcpHeaderLength) return; // Validate TCP header length
        const tcpPayloadStart = tcpHeaderStart + tcpHeaderLength;
        const tcpPayloadLength =
          ipTotalLength - ipHeaderLength - tcpHeaderLength;

        // Check for TLS Client Hello packet
        if (
          tcpPayloadLength > 5 &&
          data.length >= tcpPayloadStart + tcpPayloadLength &&
          data[tcpPayloadStart] === 0x16 &&
          data[tcpPayloadStart + 1] === 0x03
        ) {
          // TLS
          const handshakeType = data[tcpPayloadStart + 5];
          if (handshakeType === 0x01) {
            // Client Hello
            const serverName = extractServerNameFromClientHello(
              data.slice(tcpPayloadStart, tcpPayloadStart + tcpPayloadLength)
            );

            if (
              serverName &&
              (serverName.includes("netflix") ||
                serverName.includes("nflx") ||
                serverName.includes("nflxvideo") ||
                serverName.includes("nflximg") ||
                serverName.includes("nflxext") ||
                serverName.includes("nflxso") ||
                serverName.includes("nflximg.net") ||
                serverName.includes("nflxext.com") ||
                serverName.includes("nflxvideo.net") ||
                serverName.includes("nflxso.net") ||
                serverName.includes("nflximg.com") ||
                serverName.includes("nflxext.net") ||
                serverName.includes("youtube") ||
                serverName.includes("yt") ||
                serverName.includes("ytimg") ||
                serverName.includes("yt3") ||
                serverName.includes("youtu.be") ||
                serverName.includes("googlevideo") ||
                serverName.includes("youtube-nocookie.com") ||
                serverName.includes("ytstatic") ||
                serverName.includes("ytimg") ||
                serverName.includes("ytimg.l.google.com"))
            ) {
              const packetInfo = {
                Time: timestamp.toLocaleTimeString(),
                Source: sourceIP,
                Destination: destinationIP,
                Protocol: "TCP",
                Length: data.length,
                "Server Name": serverName,
                Info: "Client Hello",
              };
              packetDetails.push(packetInfo);

              if (
                serverName.includes("netflix") ||
                serverName.includes("nflx") ||
                serverName.includes("nflxvideo") ||
                serverName.includes("nflximg") ||
                serverName.includes("nflxext") ||
                serverName.includes("nflxso") ||
                serverName.includes("nflximg.net") ||
                serverName.includes("nflxext.com") ||
                serverName.includes("nflxvideo.net") ||
                serverName.includes("nflxso.net") ||
                serverName.includes("nflximg.com") ||
                serverName.includes("nflxext.net")
              ) {
                numberOfNetflixPackets++;
              } else if (
                serverName.includes("youtube") ||
                serverName.includes("yt") ||
                serverName.includes("ytimg") ||
                serverName.includes("yt3") ||
                serverName.includes("youtu.be") ||
                serverName.includes("googlevideo") ||
                serverName.includes("youtube-nocookie.com") ||
                serverName.includes("ytstatic") ||
                serverName.includes("ytimg") ||
                serverName.includes("ytimg.l.google.com")
              ) {
                numberOfYouTubePackets++;
              }
            }
          }
        }
      } else if (protocol === 17) {
        // UDP
        numberOfUdpPackets++;
        const udpHeaderStart = ipHeaderStart + ipHeaderLength;
        if (data.length < udpHeaderStart + 8) return; // Minimum length for UDP header
        const udpPayloadStart = udpHeaderStart + 8;
        const udpPayloadLength = ipTotalLength - ipHeaderLength - 8;

        // Check for DNS queries
        const domainName = extractDomainNameFromDNS(
          data.slice(udpPayloadStart, udpPayloadStart + udpPayloadLength)
        );

        if (
          domainName &&
          (domainName.includes("netflix") ||
            domainName.includes("nflx") ||
            domainName.includes("nflxvideo") ||
            domainName.includes("nflximg") ||
            domainName.includes("nflxext") ||
            domainName.includes("nflxso") ||
            domainName.includes("nflximg.net") ||
            domainName.includes("nflxext.com") ||
            domainName.includes("nflxvideo.net") ||
            domainName.includes("nflxso.net") ||
            domainName.includes("nflximg.com") ||
            domainName.includes("nflxext.net") ||
            domainName.includes("youtube") ||
            domainName.includes("yt") ||
            domainName.includes("ytimg") ||
            domainName.includes("yt3") ||
            domainName.includes("youtu.be") ||
            domainName.includes("googlevideo") ||
            domainName.includes("youtube-nocookie.com") ||
            domainName.includes("ytstatic") ||
            domainName.includes("ytimg") ||
            domainName.includes("ytimg.l.google.com"))
        ) {
          const packetInfo = {
            Time: timestamp.toLocaleTimeString(),
            Source: sourceIP,
            Destination: destinationIP,
            Protocol: "UDP",
            Length: data.length,
            "Server Name": domainName,
            Info: "DNS Query",
          };
          packetDetails.push(packetInfo);

          if (
            domainName.includes("netflix") ||
            domainName.includes("nflx") ||
            domainName.includes("nflxvideo") ||
            domainName.includes("nflximg") ||
            domainName.includes("nflxext") ||
            domainName.includes("nflxso") ||
            domainName.includes("nflximg.net") ||
            domainName.includes("nflxext.com") ||
            domainName.includes("nflxvideo.net") ||
            domainName.includes("nflxso.net") ||
            domainName.includes("nflximg.com") ||
            domainName.includes("nflxext.net")
          ) {
            numberOfNetflixPackets++;
          } else if (
            domainName.includes("youtube") ||
            domainName.includes("yt") ||
            domainName.includes("ytimg") ||
            domainName.includes("yt3") ||
            domainName.includes("youtu.be") ||
            domainName.includes("googlevideo") ||
            domainName.includes("youtube-nocookie.com") ||
            domainName.includes("ytstatic") ||
            domainName.includes("ytimg") ||
            domainName.includes("ytimg.l.google.com")
          ) {
            numberOfYouTubePackets++;
          }
        }
      }
    }
  });

  parser.on("end", () => {
    if (!startTime || !endTime) {
      res.status(400).send("No valid packets found in the file.");
      return;
    }

    // Calculate duration in seconds
    const duration = (endTime - startTime) / 1000;

    // Calculate traffic throughput (bytes per second)
    const trafficThroughput =
      duration !== 0 ? (numberOfIpBytes / duration).toFixed(2) : 0;

    parsedData = {
      numberOfNetflixPackets,
      numberOfYouTubePackets,
      numberOfIpPackets,
      numberOfIpBytes,
      numberOfUdpPackets,
      startTime:
        startTime instanceof Date ? startTime.toLocaleTimeString() : "",
      endTime: endTime instanceof Date ? endTime.toLocaleTimeString() : "",
      trafficThroughput,
    };

    // Create an Excel file
    const wb = xlsx.utils.book_new();
    const ws = xlsx.utils.json_to_sheet(packetDetails);
    xlsx.utils.book_append_sheet(wb, ws, "Packets");
    const excelBuffer = xlsx.write(wb, { type: "buffer", bookType: "xlsx" });

    res.json({
      message: "File uploaded and processed successfully.",
      data: parsedData,
      excelBuffer: excelBuffer.toString("base64"), // Return base64 encoded buffer
    });
  });

  parser.on("error", (error) => {
    console.error("Error reading the pcap file:", error);
    res.status(500).send("Error processing the file.");
  });
});

app.get("/results", (req, res) => {
  res.status(200).json({ parsedData, packetDetails });
});

app.get("/", (req, res) => {
  res.status(200).json({ msg: "deployed!" });
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

// Function to extract server name from TLS Client Hello
function extractServerNameFromClientHello(data) {
  let offset = 43; // Skip the handshake header and fixed parts
  if (data.length < offset + 1) return null; // Validate offset
  const sessionIdLength = data[offset];
  offset += 1 + sessionIdLength; // Skip Session ID
  if (data.length < offset + 2) return null; // Validate offset
  const cipherSuitesLength = data.readUInt16BE(offset);
  offset += 2 + cipherSuitesLength; // Skip Cipher Suites
  if (data.length < offset + 1) return null; // Validate offset
  const compressionMethodsLength = data[offset];
  offset += 1 + compressionMethodsLength;

  if (offset + 2 > data.length) return null; // Validate offset
  const extensionsLength = data.readUInt16BE(offset);
  offset += 2;
  const extensionsEnd = offset + extensionsLength;

  while (offset + 4 <= extensionsEnd && offset + 4 <= data.length) {
    const extensionType = data.readUInt16BE(offset);
    const extensionLength = data.readUInt16BE(offset + 2);
    offset += 4;
    if (extensionType === 0x0000) {
      // Server Name extension
      if (offset + 2 > data.length) return null; // Validate offset
      const serverNameListLength = data.readUInt16BE(offset);
      offset += 2;
      if (
        offset + serverNameListLength > extensionsEnd ||
        offset + serverNameListLength > data.length
      )
        return null; // Validate offset
      const serverNameType = data[offset];
      if (serverNameType !== 0) return null;
      if (offset + 3 > data.length) return null; // Validate offset
      const serverNameLength = data.readUInt16BE(offset + 1);
      offset += 3;
      if (offset + serverNameLength > data.length) return null; // Validate offset
      return data.slice(offset, offset + serverNameLength).toString();
    }
    offset += extensionLength;
  }
  return null;
}

// Function to extract domain name from DNS query
function extractDomainNameFromDNS(data) {
  if (data.length < 12) return null; // Minimum length for DNS header
  const qdCount = data.readUInt16BE(4);
  if (qdCount < 1) return null; // No questions
  let offset = 12;

  while (data[offset] !== 0 && offset < data.length) {
    const length = data[offset];
    if ((length & 0xc0) === 0xc0) {
      // Handle pointers
      offset += 2;
      break;
    } else {
      offset += length + 1;
    }
    if (offset >= data.length) return null; // Validate offset
  }
  offset++; // Skip the null byte that terminates the name

  if (offset + 4 > data.length) return null; // Minimum length for query
  const qType = data.readUInt16BE(offset);
  const qClass = data.readUInt16BE(offset + 2);
  if (qType !== 1 || qClass !== 1) return null; // Not A record or IN class

  const labels = [];
  offset = 12; // Reset offset to read the domain name again

  while (data[offset] !== 0 && offset < data.length) {
    const length = data[offset];
    if ((length & 0xc0) === 0xc0) {
      // Handle pointers
      const pointer = data.readUInt16BE(offset) & 0x3fff; // Get pointer offset
      if (pointer >= data.length) return null; // Validate pointer
      offset = pointer;
    } else {
      labels.push(data.toString("utf8", offset + 1, offset + 1 + length));
      offset += length + 1;
    }
    if (offset >= data.length) return null; // Validate offset
  }

  return labels.join(".");
}
