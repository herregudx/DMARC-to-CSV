# DMARC-to-CSV
A DMARC parser. Converts DMARC RUA XML-files to an reasy readable table and export the results to a timestamped CSV-file. The report displays the following columns:

**Reporter, Source IP, Count, Disposition, Header From, SPF Domain, SPF, DKIM Domain, DKIM, DMARC Relaxed and DMARC Strict**.

DMARC results are shown as pass or fail, and the terminal output is colored to make it easier to read. If either SPF or DKIM result is "temperror" the DMARC results will show "none (override)" to indicate that DMARC policy would not be enforced (as specified by RFC 7489 - 6.6.2).

Example terminal output (without coloring):
```
+--------------------+--------------------------+---------+---------------+-----------------+------------------------------------+-----------+---------------------------+--------+-----------------+-----------------+
| Reporter           | Source IP                |   Count | Disposition   | Header From     | SPF Domain                         | SPF       | DKIM Domain               | DKIM   | DMARC Relaxed   | DMARC Strict    |
+====================+==========================+=========+===============+=================+====================================+===========+===========================+========+=================+=================+
| AMAZON-SES         | 198.168.1.217            |       1 | none          | yourdomain.com  | yourdomain.com                     | pass      |                           | none   | pass            | pass            |
+--------------------+--------------------------+---------+---------------+-----------------+------------------------------------+-----------+---------------------------+--------+-----------------+-----------------+
| AMAZON-SES         | 123.145.67.189           |       1 | none          | yourdomain.com  | yourdomain.com                     | pass      | yourdomain.com            | pass   | pass            | pass            |
+--------------------+--------------------------+---------+---------------+-----------------+------------------------------------+-----------+---------------------------+--------+-----------------+-----------------+
| AMAZON-SES         | 149.23.45.67             |       1 | none          | yourdomain.com  | sub.yourdomain.com                 | softfail  |                           | none   | fail            | fail            |
+--------------------+--------------------------+---------+---------------+-----------------+------------------------------------+-----------+---------------------------+--------+-----------------+-----------------+
| Enterprise Outlook | 2b06:1846:cc70:8600::116 |       1 | none          | yourdomain.com  | yourdomain.com                     | temperror |                           | none   | none (override) | none (override) |
+--------------------+--------------------------+---------+---------------+-----------------+------------------------------------+-----------+---------------------------+--------+-----------------+-----------------+
| Enterprise Outlook | 165.123.45.62            |       1 | none          | yourdomain.com  | anotherdomain.com                  | pass      |                           | none   | fail            | fail            |
+--------------------+--------------------------+---------+---------------+-----------------+------------------------------------+-----------+---------------------------+--------+-----------------+-----------------+
```

### Note: 
The script will read all XML-files located in ./dmarc_reports. If you put DMARC-report zipped files in /dmarc_reports you can run unzip-reports.py to extract them all at once to the same folder.
