# DMARC-to-CSV
A DMARC parser. Converts DMARC RUA XML-files to an reasy readable table and export the results to a timestamped CSV-file. The report displays the following columns:

**Reporter, Source IP, Count, Disposition, Header From, Envelope From, Envelope To, SPF Domain, SPF, DKIM Domain, DKIM, DMARC Relaxed and DMARC Strict**.

DMARC results are shown as pass or fail, and the terminal output is colored to make it easier to read. If either SPF or DKIM result is "temperror" the DMARC results will show "none (override)" to indicate that DMARC policy would not be enforced (as specified by RFC 7489 - 6.6.2).

Example terminal output (without coloring):
```
+---------------+-----------------------+---------+---------------+---------------+------------------+---------------+------------------+----------+---------------------------+--------+-----------------+----------------+
| Reporter      | Source IP             |   Count | Disposition   | Header From   | Envelope From    | Envelope To   | SPF Domain       | SPF      | DKIM Domain               | DKIM   | DMARC Relaxed   | DMARC Strict   |
+===============+=======================+=========+===============+===============+==================+===============+==================+==========+===========================+========+=================+================+
| AMAZON-SES    | 12.34.156.123         |       1 | quarantine    | domain.no     | example1.com     |               | example1.com     | pass     | example1.onmicrosoft.com  | pass   | fail            | fail           |
+---------------+-----------------------+---------+---------------+---------------+------------------+---------------+------------------+----------+---------------------------+--------+-----------------+----------------+
| AMAZON-SES    | 123.45.123.45         |       1 | none          | domain.no     | subdom.domain.no |               | subdom.domain.no | softfail | domain.no                 | pass   | pass            | pass           |
+---------------+-----------------------+---------+---------------+---------------+------------------+---------------+------------------+----------+---------------------------+--------+-----------------+----------------+
| EXAMPLE.COM   | 1a23:123:f123:c56b::1 |       1 | none          | domain.no     |                  |               | domain.no        | pass     | domain.no                 | pass   | pass            | pass           |
+---------------+-----------------------+---------+---------------+---------------+------------------+---------------+------------------+----------+---------------------------+--------+-----------------+----------------+
| EXAMPLE.COM   | 1a23:123:f123:c56a::2 |       1 | none          | domain.no     |                  |               | domain.no        | pass     | domain.no                 | pass   | pass            | pass           |
+---------------+-----------------------+---------+---------------+---------------+------------------+---------------+------------------+----------+---------------------------+--------+-----------------+----------------+
| Outlook.com   | 12.123.45.167         |       2 | none          | domain.no     | domain.no        | hotmail.com   | domain.no        | pass     | domain.no                 | pass   | pass            | pass           |
+---------------+-----------------------+---------+---------------+---------------+------------------+---------------+------------------+----------+---------------------------+--------+-----------------+----------------+
```

### Short explanation of the columns:

- Reporter: Organization that generated the DMARC report.
- Source IP: IP address of the server that sent the email.
- Count: Number of emails represented by the record.
- Disposition: Action taken by the receiving server (none, quarantine, or reject).
- Header From: Domain shown in the visible From address.
- Envelope From: Domain used as the SMTP envelope sender (Return-Path).
- Envelope To: Recipient domain from the SMTP envelope (may not be included by all reporters).
- SPF Domain: Domain that was evaluated by SPF.
- SPF: SPF authentication result.
- DKIM Domain: Domain used in the DKIM signature (multiple domains may be shown).
- DKIM: DKIM authentication result.
- DMARC Relaxed: Calculated DMARC result using relaxed domain alignment.
- DMARC Strict: Calculated DMARC result using strict domain alignment.


### Note: 
The script will read all XML-files located in ./dmarc_reports. If you put DMARC-report zipped files in /dmarc_reports you can run unzip-reports.py to extract them all at once to the same folder.
