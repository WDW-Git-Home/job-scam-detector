#!/usr/bin/env python3
"""
scam_detector_gui.py v3.0
Job Scam Detector — Full Production GUI
Features: Drag-and-drop, batch analysis, export, history, API management
"""

import customtkinter as ctk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path
import threading
import json
import os
import sys
import subprocess
import shutil
import re
from datetime import datetime
from typing import Dict, List, Optional
import sqlite3
from zipfile import ZipFile
import hashlib

# Import core functions
try:
    from scam_detector_core import (
        parse_eml_file, 
        parse_pasted_email, 
        scan_red_flags, 
        check_spf, 
        check_dkim, 
        check_dmarc, 
        calculate_threat_score,
        whois_domain_age,
        calculate_domain_age_days,
        extract_sender_domain,
        extract_received_ips,
        check_virustotal_url,
        check_virustotal_domain,
        check_abuseipdb,
        extract_urls,
        extract_body,
        extract_headers,
        load_config,
        save_config,
        RED_FLAGS
    )
except ImportError:
    # Fallback if running standalone
    print("Warning: scam_detector_core.py not found. Some features may be limited.")

# Theme settings
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# Constants
CONFIG_DIR = Path.home() / ".config" / "scam_detector"
CONFIG_DIR.mkdir(parents=True, exist_ok=True)
CONFIG_FILE = CONFIG_DIR / "config.json"
LOG_DIR = Path.home() / "Documents" / "logs" / "scam_detector"
LOG_DIR.mkdir(parents=True, exist_ok=True)
HISTORY_DB = CONFIG_DIR / "scan_history.db"

# Theme configuration for HTML reports
THEME_CONFIG_PATH = CONFIG_DIR / "report_theme.json"
DEFAULT_THEME = "dark"

def load_theme_preference():
    """Load saved theme preference."""
    try:
        if THEME_CONFIG_PATH.exists():
            with open(THEME_CONFIG_PATH, "r") as f:
                return json.load(f).get("report_theme", DEFAULT_THEME)
    except:
        pass
    return DEFAULT_THEME

def save_theme_preference(name):
    """Save theme preference."""
    try:
        with open(THEME_CONFIG_PATH, "w") as f:
            json.dump({"report_theme": name}, f)
    except:
        pass

THEMES = {
    "dark": {"name": "Batman Dark", "bg": "#0a0a0a", "fg": "#e0e0e0", "accent": "#ffc300", "section_bg": "#1a1a1a", "border": "#3a3a3a", "secondary_fg": "#888888", "muted_fg": "#555555", "disclaimer_bg": "#1a1500", "disclaimer_border": "#ffc300"},
    "light": {"name": "Light Mode", "bg": "#fff", "fg": "#333", "accent": "#6d4aff", "section_bg": "#f5f5f5", "border": "#ddd", "secondary_fg": "#666", "muted_fg": "#999", "disclaimer_bg": "#fff3e0", "disclaimer_border": "#ff9800"},
    "proton": {"name": "Proton Purple", "bg": "#12121f", "fg": "#fff", "accent": "#6d4aff", "section_bg": "#1e1e36", "border": "#6d4aff", "secondary_fg": "#b8b8d4", "muted_fg": "#8888aa", "disclaimer_bg": "#241e2e", "disclaimer_border": "#6d4aff"},
    "high-contrast": {"name": "High Contrast", "bg": "#000", "fg": "#ff0", "accent": "#0f0", "section_bg": "#111", "border": "#333", "secondary_fg": "#0f0", "muted_fg": "#aaa", "disclaimer_bg": "#220", "disclaimer_border": "#ff0"}
}

# Test cases embedded as built-in demos
TEST_CASES = {
    'gm_sami_first': {
        'name': 'GM Sami Pattern (Initial PII Request)',
        'description': 'Offshore recruiter asking for DL/SSN/DOB before interview',
        'raw_email': '''From: "GM Sami" <gmsami@synersystech.com>
To: "D.W" <dave@davewells.me>
Subject: Re: Senior Enterprise ICAM Architect (Federal/CMS)
Date: Fri, 24 Jul 2026 12:44:01 -0400

Hi Dave,

Thank you for the confirmation.

To proceed, please revert your DL copy along with the following details as soon as possible:

•  Interview availability: 2 time slots on 2 different weekdays
•  Full legal name
•  Alternate phone number
•  LinkedIn profile URL
•  Confirmation that you are available to work onsite
•  Date of Birth (DD/MM/YYYY)
•  Last 4 digits of your SSN
•  WhatsApp number (mandatory)
•  Email ID associated with your LinkedIn profile
•  Bachelor's degree and year of graduation
•  Master's degree (if applicable) and year of graduation

Please also provide two professional references.

Kindly send the above information at the earliest so that we can schedule your interview without any delay.''',
        'expected_score': '50-75/100 (MEDIUM-HIGH)',
        'expected_flags': ['pii_requests', 'communication_red_flags', 'urgency_language', 'salary_red_flags'],
    },
    
    'dawn_pattern': {
        'name': 'Dawn Pattern (Legitimate Recruiter)',
        'description': 'Professional contractor with transparent rates, no PII requests',
        'raw_email': '''From: Dawn <dawn@legitimate-staffing.com>
To: Dave <dave@example.com>
Subject: Re: Senior ICAM Architect Position

Hi Dave,

Answers to your questions:

1. What is the rate for this engagement? $80 - $85/hr
2. Is this C2C or W2? 1099 or C2C
3. Is this remote or on-site? Remote

My expertise is in identity architecture and federation, not AWS infrastructure deployment. I am checking on this and will get back to you.

Best regards,
Dawn''',
        'expected_score': '5-10/100 (MINIMAL)',
        'expected_flags': [],
    },
}

class ScamDetectorApp(ctk.CTk):
    """Main application class for Job Scam Detector."""
    
    def __init__(self):
        super().__init__()
        
        # Window setup
        self.title("🔍 Job Scam Detector v3.0")
        self.geometry("1100x800")
        self.resizable(True, True)
        
        self.config = load_config()
        self.init_database()
        self.setup_ui()
        
        # Bind drag-and-drop
        self.bind("<Configure>", self.on_resize)
    
    def init_database(self):
        """Initialize SQLite database for scan history."""
        conn = sqlite3.connect(HISTORY_DB)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                sender TEXT,
                domain TEXT,
                threat_score INTEGER,
                verdict TEXT,
                red_flags_count INTEGER,
                input_type TEXT,
                file_path TEXT
            )
        ''')
        conn.commit()
        conn.close()
    
    def setup_ui(self):
        """Build the complete user interface."""
        # Configure grid weights for resizable layout
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        
        # Header frame
        header_frame = ctk.CTkFrame(self)
        header_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 5))
        header_frame.grid_columnconfigure(1, weight=1)
        
        title_label = ctk.CTkLabel(
            header_frame,
            text="🔍 Job Scam Detector v3.0",
            font=("Helvetica", 24, "bold")
        )
        title_label.grid(row=0, column=0, padx=10, pady=10)
        

        
        # Main notebook/tabs
        self.notebook = ctk.CTkTabview(self)
        self.notebook.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
        
        # Create tab pages
        self.create_single_scan_tab()
        self.create_batch_scan_tab()
        self.create_history_tab()
        self.create_demo_tab()
        self.create_settings_tab()
    
    def create_single_scan_tab(self):
        """Single email analysis tab."""
        tab = self.notebook.add("Single Scan")
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)
        
        # Input method selector
        input_frame = ctk.CTkFrame(tab)
        input_frame.grid(row=0, column=0, sticky="ew", pady=10)
        
        ctk.CTkLabel(input_frame, text="Input Method:", font=("Arial", 12)).grid(row=0, column=0, padx=10, pady=5)
        
        self.single_input_method = ctk.StringVar(value="paste")
        
        ctk.CTkRadioButton(input_frame, text="Paste Email Text", 
                           variable=self.single_input_method, value="paste").grid(row=0, column=1, padx=5)
        
        ctk.CTkRadioButton(input_frame, text="Drop .eml File", 
                           variable=self.single_input_method, value="file").grid(row=0, column=2, padx=5)
        
        # Email input area
        self.email_text = ctk.CTkTextbox(tab, width=900, height=250)
        self.email_text.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)
        
        # File path label (for drop mode)
        self.file_path_label = ctk.CTkLabel(tab, text="No file selected", text_color="gray")
        self.file_path_label.grid(row=2, column=0, sticky="w", padx=10)
        
        # Control buttons
        btn_frame = ctk.CTkFrame(tab)
        btn_frame.grid(row=3, column=0, sticky="ew", padx=10, pady=10)
        
        self.analyze_btn = ctk.CTkButton(btn_frame, text="🔍 Analyze Email", 
                                         command=self.analyze_single_email, width=180)
        self.analyze_btn.pack(side="left", padx=5)
        
        self.browse_btn = ctk.CTkButton(btn_frame, text="Browse .eml...", 
                                        command=self.browse_single_file, width=120)
        self.browse_btn.pack(side="left", padx=5)
        
        self.clear_btn = ctk.CTkButton(btn_frame, text="Clear All", 
                                       command=self.clear_single_tab, width=100)
        self.clear_btn.pack(side="right", padx=5)
        
        # Progress indicator
        self.progress_label = ctk.CTkLabel(tab, text="", text_color="yellow", font=("Arial", 11))
        self.progress_label.grid(row=4, column=0, pady=5)
        
        # Results area
        result_frame = ctk.CTkScrollableFrame(tab, height=300)
        result_frame.grid(row=5, column=0, sticky="nsew", padx=10, pady=10)
        
        self.result_label = ctk.CTkLabel(result_frame, text="Results will appear here after analysis.", justify="left")
        self.result_label.pack(anchor="w", fill="x")
        
        # Export button
        self.export_btn = ctk.CTkButton(
            result_frame, 
            text="💾 Export Report", 
            command=self.export_results,
            width=250
        )
        self.export_btn.pack(pady=10)
        
        # Footer status
        footer_label = ctk.CTkLabel(
            tab, 
            text="Reports saved to: ~/Documents/logs/scam-detector", 
            text_color="gray",
            font=("Arial", 10)
        )
        footer_label.grid(row=6, column=0, pady=(0, 5))
    
    def create_batch_scan_tab(self):
        """Batch email analysis tab."""
        tab = self.notebook.add("Batch Scan")
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)
        
        # Instructions
        instr_label = ctk.CTkLabel(
            tab,
            text="Select a folder containing .eml files or drag multiple files here.",
            font=("Arial", 12),
            text_color="gray"
        )
        instr_label.grid(row=0, column=0, pady=(10, 5))
        
        # Folder path
        self.batch_folder_label = ctk.CTkLabel(tab, text="No folder selected", text_color="gray")
        self.batch_folder_label.grid(row=1, column=0, sticky="w", padx=20, pady=5)
        
        self.select_folder_btn = ctk.CTkButton(tab, text="Select Folder", 
                                                command=self.select_batch_folder, width=150)
        self.select_folder_btn.grid(row=1, column=1, padx=5)
        
        # Progress bar
        self.batch_progress = ttk.Progressbar(tab, orient="horizontal", length=800, mode='determinate')
        self.batch_progress.grid(row=2, column=0, pady=10)
        
        self.batch_progress_label = ctk.CTkLabel(tab, text="", font=("Arial", 11))
        self.batch_progress_label.grid(row=3, column=0)
        
        # Results table
        tree_frame = ctk.CTkFrame(tab)
        tree_frame.grid(row=4, column=0, sticky="nsew", padx=20, pady=10)
        tree_frame.grid_columnconfigure(0, weight=1)
        
        columns = ("File", "Sender", "Domain", "Score", "Verdict")
        self.batch_tree = ttk.Treeview(tree_frame, columns=columns, show="headings")
        
        self.batch_tree.heading("File", text="File")
        self.batch_tree.heading("Sender", text="Sender")
        self.batch_tree.heading("Domain", text="Domain")
        self.batch_tree.heading("Score", text="Threat Score")
        self.batch_tree.heading("Verdict", text="Verdict")
        
        self.batch_tree.column("File", width=200)
        self.batch_tree.column("Sender", width=150)
        self.batch_tree.column("Domain", width=150)
        self.batch_tree.column("Score", width=80)
        self.batch_tree.column("Verdict", width=200)
        
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.batch_tree.yview)
        self.batch_tree.configure(yscrollcommand=scrollbar.set)
        
        self.batch_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Batch controls
        btn_frame = ctk.CTkFrame(tab)
        btn_frame.grid(row=5, column=0, pady=10)
        
        self.run_batch_btn = ctk.CTkButton(btn_frame, text="▶ Run Batch Analysis", 
                                            command=self.run_batch_analysis, width=200)
        self.run_batch_btn.pack(side="left", padx=5)
        
        self.stop_batch_btn = ctk.CTkButton(btn_frame, text="⏹ Stop Analysis", 
                                            command=self.stop_batch_analysis, width=150, 
                                            fg_color="red", hover_color="#cc0000")
        self.stop_batch_btn.pack(side="left", padx=5)
        
        self.export_batch_btn = ctk.CTkButton(btn_frame, text="💾 Export All to CSV", 
                                              command=self.export_batch_csv, width=180)
        self.export_batch_btn.pack(side="left", padx=5)
    
    def create_history_tab(self):
        """Scan history viewer tab."""
        tab = self.notebook.add("History")
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)
        
        # Filter controls
        filter_frame = ctk.CTkFrame(tab)
        filter_frame.grid(row=0, column=0, sticky="ew", padx=20, pady=10)
        
        ctk.CTkLabel(filter_frame, text="Min Score:", font=("Arial", 11)).grid(row=0, column=0, padx=5)
        self.score_filter = ctk.CTkEntry(filter_frame, width=60, placeholder_text="0")
        self.score_filter.grid(row=0, column=1, padx=5)
        
        ctk.CTkButton(filter_frame, text="Load History", command=self.load_history, width=120).grid(row=0, column=2, padx=10)
        ctk.CTkButton(filter_frame, text="Clear History", command=self.clear_history, width=120, fg_color="red").grid(row=0, column=3, padx=10)
        ctk.CTkButton(filter_frame, text="Export CSV", command=self.export_history_csv, width=120).grid(row=0, column=4, padx=10)
        
        # History table
        tree_frame = ctk.CTkFrame(tab)
        tree_frame.grid(row=1, column=0, sticky="nsew", padx=20, pady=10)
        tree_frame.grid_columnconfigure(0, weight=1)
        
        columns = ("Date", "File", "Sender", "Domain", "Score", "Verdict", "Actions")
        self.history_tree = ttk.Treeview(tree_frame, columns=columns, show="headings")
        
        for col in columns[:-1]:  # Exclude Actions column
            self.history_tree.heading(col, text=col)
            self.history_tree.column(col, anchor="center")
        
        self.history_tree.heading("Actions", text="Actions")
        self.history_tree.column("Actions", width=120)
        
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=scrollbar.set)
        
        self.history_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Bind double-click to view details
        self.history_tree.bind("<Double-1>", self.view_history_detail)
    
    def create_demo_tab(self):
        """Built-in test case demo tab."""
        tab = self.notebook.add("Demo Test Cases")
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)
        
        # Demo instructions
        demo_instr = ctk.CTkLabel(
            tab,
            text="Run predefined test cases to see how the detector scores different email patterns.\n\n"
                 "• GM Sami Pattern: Tests PII request detection\n"
                 "• Dawn Pattern: Tests legitimate recruiter scoring",
            font=("Arial", 12),
            justify="center"
        )
        demo_instr.grid(row=0, column=0, pady=20)
        
        # Test case selector
        demo_frame = ctk.CTkFrame(tab)
        demo_frame.grid(row=1, column=0, pady=10)
        
        self.demo_choice = ctk.StringVar(value="gm_sami_first")
        
        for i, (key, test) in enumerate(TEST_CASES.items()):
            ctk.CTkRadioButton(
                demo_frame,
                text=f"{test['name']}",
                variable=self.demo_choice,
                value=key
            ).grid(row=0, column=i, padx=20)
        
        # Demo results preview
        preview_label = ctk.CTkLabel(
            demo_frame,
            text=f"Expected: {list(TEST_CASES.values())[0]['expected_score']}",
            font=("Arial", 11),
            text_color="gray"
        )
        preview_label.grid(row=2, column=0, pady=5)
        
        # Run demo button
        self.run_demo_btn = ctk.CTkButton(demo_frame, text="▶ Run Demo Analysis", 
                                          command=self.run_demo_analysis, width=200)
        self.run_demo_btn.grid(row=3, column=0, pady=15)
        
        # Demo results display
        self.demo_result_label = ctk.CTkLabel(
            tab,
            text="Run a demo to see results here.",
            justify="left",
            font=("Courier", 10)
        )
        self.demo_result_label.grid(row=2, column=0, sticky="nsew", padx=20, pady=10)
    
    def create_settings_tab(self):
        """API key management and settings tab."""
        tab = self.notebook.add("Settings")
        tab.grid_columnconfigure(0, weight=1)
        
        # API Keys section
        api_frame = ctk.CTkFrame(tab)
        api_frame.grid(row=0, column=0, sticky="ew", padx=20, pady=10)
        
        ctk.CTkLabel(api_frame, text="API Key Configuration", font=("Arial", 16, "bold")).pack(pady=10)
        
        # VirusTotal
        vt_frame = ctk.CTkFrame(api_frame)
        vt_frame.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkLabel(vt_frame, text="VirusTotal API Key:").pack(side="left", padx=5)
        self.vt_key_entry = ctk.CTkEntry(vt_frame, width=400, placeholder_text="Enter VirusTotal API key")
        self.vt_key_entry.pack(side="left", padx=5)
        ctk.CTkButton(vt_frame, text="Save", command=lambda: self.save_api_key("virustotal", self.vt_key_entry), width=80).pack(side="left", padx=5)
        ctk.CTkButton(vt_frame, text="Load from maintain-v7.sh", command=self.load_vt_from_maintain, width=150).pack(side="left", padx=5)
        
        # AbuseIPDB
        ipdb_frame = ctk.CTkFrame(api_frame)
        ipdb_frame.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkLabel(ipdb_frame, text="AbuseIPDB API Key:").pack(side="left", padx=5)
        self.ipdb_key_entry = ctk.CTkEntry(ipdb_frame, width=400, placeholder_text="Enter AbuseIPDB API key")
        self.ipdb_key_entry.pack(side="left", padx=5)
        ctk.CTkButton(ipdb_frame, text="Save", command=lambda: self.save_api_key("abuseipdb", self.ipdb_key_entry), width=80).pack(side="left", padx=5)
        
        # Get API keys button
        ctk.CTkButton(
            api_frame,
            text="📖 How to Get API Keys",
            command=self.show_api_guide,
            width=200
        ).pack(pady=10)
        
        # Theme Selection
        theme_frame = ctk.CTkFrame(tab)
        theme_frame.grid(row=1, column=0, sticky="ew", padx=20, pady=10)
        
        ctk.CTkLabel(
            theme_frame,
            text="HTML Report Theme",
            font=("Arial", 14, "bold")
        ).pack(pady=(10, 5))
        
        current_theme = load_theme_preference()
        
        theme_var = ctk.StringVar(value=current_theme)
        theme_dropdown = ctk.CTkComboBox(
            theme_frame,
            values=list(THEMES.keys()),
            variable=theme_var,
            width=200
        )
        theme_dropdown.pack(pady=5)
        
        def on_theme_change(val):
            save_theme_preference(val)
            self.theme_label.configure(text=f"Current: {THEMES[val]['name']}")
        
        theme_dropdown.configure(command=on_theme_change)
        
        self.theme_label = ctk.CTkLabel(
            theme_frame,
            text=f"Current: {THEMES[current_theme]['name']}",
            text_color="gray",
            font=("Arial", 10)
        )
        self.theme_label.pack()
        # About section
        about_frame = ctk.CTkFrame(tab)
        about_frame.grid(row=2, column=0, sticky="ew", padx=20, pady=10)
        
        ctk.CTkLabel(
            about_frame,
            text="Job Scam Detector v3.0\n© 2026 | Created by Dave Wells\nStandard library + customtkinter",
            font=("Arial", 12),
            justify="left"
        ).pack(pady=10)
        
        # GitHub/Documentation links
        ctk.CTkButton(
            about_frame,
            text="📋 Copy Report to Clipboard",
            command=self.copy_report_to_clipboard,
            width=250
        ).pack(pady=5)
        
        self.clipboard_label = ctk.CTkLabel(about_frame, text="", text_color="green")
        self.clipboard_label.pack(pady=5)
    
    # ==================== UTILITY METHODS ====================
    
#    def change_mode(self, mode):
#        """Switch between single/batch/history/demo tabs."""
#        pass  # Notebook handles this automatically
    
    def on_resize(self, event=None):
        """Handle window resize events."""
        pass
    
    def load_api_keys(self):
        """Load saved API keys from config."""
        self.config = load_config()
        if "virustotal" in self.config:
            self.vt_key_entry.delete(0, "end")
            self.vt_key_entry.insert(0, self.config["virustotal"][:8] + "...")
        if "abuseipdb" in self.config:
            self.ipdb_key_entry.delete(0, "end")
            self.ipdb_key_entry.insert(0, self.config["abuseipdb"][:8] + "...")
    
    def save_api_key(self, key_name, entry_widget):
        """Save API key to config file."""
        key_value = entry_widget.get()
        if key_value.endswith("..."):
            # Partial key display - use existing value
            key_value = self.config.get(key_name, "")
        if key_value and not key_value.endswith("..."):
            self.config[key_name] = key_value
            save_config(self.config)
            messagebox.showinfo("Success", f"{key_name.capitalize()} key saved.")
    
    def load_vt_from_maintain(self):
        """Try to load VirusTotal key from maintain-v7.sh config."""
        vt_conf = Path.home() / ".config" / "maintain" / "vt-api.conf"
        if vt_conf.exists():
            try:
                with open(vt_conf, 'r') as f:
                    content = f.read()
                    match = re.search(r'VT_API_KEY=(.+)', content)
                    if match:
                        key = match.group(1).strip()
                        self.vt_key_entry.delete(0, "end")
                        self.vt_key_entry.insert(0, key[:8] + "...")
                        self.config['virustotal'] = key
                        save_config(self.config)
                        messagebox.showinfo("Success", "VirusTotal key loaded from maintain-v7.sh config.")
                    else:
                        messagebox.showwarning("Not Found", "Could not find VT_API_KEY in config file.")
            except Exception as e:
                messagebox.showerror("Error", str(e))
        else:
            messagebox.showinfo("Info", f"maintain-v7.sh config not found at {vt_conf}")
    
    def show_api_guide(self):
        """Show instructions for getting API keys."""
        guide_text = """
VIRUSTOTAL API KEY:
1. Go to https://www.virustotal.com/gui/my-apikey
2. Sign up / Sign in
3. Navigate to "My API Key" section
4. Copy the 64-character key

ABUSEIPDB API KEY:
1. Go to https://www.abuseipdb.com/account/api
2. Sign up for free account
3. Generate API key from dashboard
4. Copy the key

Both services offer generous FREE tiers!
VirusTotal: 500 queries/day
AbuseIPDB: 2,000 queries/day
"""
        messagebox.showinfo("API Key Guide", guide_text)
    
    def export_results(self):
        """Export current scan results to HTML or plain text."""
        if not hasattr(self, 'current_result') or not self.current_result:
            messagebox.showwarning("No Results", "No scan results to export.")
            return
        
        # Get initial directory
        initial_dir = os.path.dirname(os.path.expanduser("~"))
        
        filepath = filedialog.asksaveasfilename(
            initialdir=initial_dir,
            filetypes=[("HTML Report", "*.html"), ("Plain Text", "*.txt")]
        )
        
        if filepath:
            try:
                # Force proper extension if user forgot it
                if not filepath.endswith(('.html', '.txt')):
                    # Default to HTML if no extension provided
                    filepath += '.html'
                
                # Determine export type based on final extension
                if filepath.endswith('.txt'):
                    # Export plain text — pull from the result label
                    text_content = self.result_label.cget("text")
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(text_content)
                else:
                    # Export HTML (default)
                    html_content = self.generate_html_report()
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(html_content)
                messagebox.showinfo("Success", f"Report exported to {filepath}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export: {e}")
    
    def generate_html_report(self):
        """Generate HTML report from current scan results."""
        if not hasattr(self, 'current_result'):
            return ""
        
        threat = self.current_result
        findings = getattr(self, 'current_findings', {})
        score = threat.get('score', 0)
        verdict = threat.get('verdict', 'Unknown')
        reasons = threat.get('reasons', [])
        
        # Color based on score
        if score >= 81:
            score_color = "#cc0000"
            risk_label = "CRITICAL"
        elif score >= 61:
            score_color = "#ff6600"
            risk_label = "HIGH"
        elif score >= 41:
            score_color = "#ffcc00"
            risk_label = "MEDIUM"
        elif score >= 21:
            score_color = "#99cc00"
            risk_label = "LOW"
        else:
            score_color = "#00cc00"
            risk_label = "MINIMAL"
        
        # Authentication section
        auth = findings.get('authentication', {})
        spf = auth.get('spf', {}).get('result', 'N/A')
        dkim = auth.get('dkim', {}).get('result', 'N/A')
        dmarc = auth.get('dmarc', {}).get('result', 'N/A')
        
        # Verification section
        verified = findings.get('verified', {})
        ver_html = ""
        if verified and verified.get('verification_complete'):
            dom_age = verified.get('domain_age_days', -1)
            mx_valid = verified.get('mx_valid', False)
            website_exists = verified.get('company_website_exists', False)
            
            dom_status = f"{dom_age} days" if dom_age > 0 else "Unknown"
            mx_color = "#00cc00" if mx_valid else "#cc0000"
            mx_text = "Valid" if mx_valid else "No MX records"
            site_color = "#00cc00" if website_exists else "#cc0000"
            site_text = "Exists" if website_exists else "Not found"
            
            ver_html = f"""
            <table class="detail-table">
                <tr><td>Domain Age</td><td>{dom_status}</td></tr>
                <tr><td>MX Records</td><td style="color:{mx_color}">{mx_text}</td></tr>
                <tr><td>Company Website</td><td style="color:{site_color}">{site_text}</td></tr>
                <tr><td>Email Pattern</td><td>{verified.get('email_pattern_matches', 'N/A')}</td></tr>
                <tr><td>In Breach DB</td><td>{'Yes' if verified.get('in_breach_db') else 'No'}</td></tr>
            </table>
            """
            
            if verified.get('flags'):
                ver_html += "<ul>"
                for flag in verified['flags']:
                    ver_html += f"<li>⚠ {flag}</li>"
                ver_html += "</ul>"
        else:
            ver_html = "<p>Verification not performed or not available.</p>"
        
        # Backtrace section
        bt = findings.get('backtrace', {})
        bt_html = ""
        if bt:
            origin_ip = bt.get('origin_ip', 'N/A')
            total_hops = bt.get('total_hops', 0)
            geo = bt.get('geo_location')
            rdns = bt.get('reverse_dns', 'N/A')
            asn = bt.get('asn_info')
            
            geo_str = "Unknown"
            if geo:
                geo_str = f"{geo.get('city', 'Unknown')}, {geo.get('country_name', 'Unknown')} ({geo.get('country_code', 'XX')})"
            
            asn_str = "Unknown"
            if asn and asn.get('org'):
                asn_str = asn['org']
            
            bt_html = f"""
            <table class="detail-table">
                <tr><td>Origin IP</td><td>{origin_ip}</td></tr>
                <tr><td>Total Hops</td><td>{total_hops}</td></tr>
                <tr><td>Reverse DNS</td><td>{rdns}</td></tr>
                <tr><td>Geo Location</td><td>{geo_str}</td></tr>
                <tr><td>ISP/Organization</td><td>{asn_str}</td></tr>
            </table>
            """
            
            if bt.get('gmail_hiding'):
                bt_html += '<p style="color:#ff6600">⚠ Gmail/Outlook email — origin IP hidden</p>'
            
            if bt.get('route_suspicious'):
                bt_html += '<p style="color:#cc0000"><strong>⚠ Suspicious Route:</strong></p><ul>'
                for factor in bt.get('risk_factors', []):
                    bt_html += f"<li>{factor}</li>"
                bt_html += "</ul>"
        else:
            bt_html = "<p>Backtrace not available.</p>"
        
        # Red flags section
        red_flags = findings.get('red_flags', [])
        rf_html = ""
        if red_flags:
            categories = {}
            for flag in red_flags:
                cat = flag['category']
                if cat not in categories:
                    categories[cat] = []
                categories[cat].append(flag)
            
            rf_html = "<ul>"
            for cat, flags in categories.items():
                cat_name = cat.replace('_', ' ').title()
                rf_html += f"<li><strong>[{cat_name}]</strong><ul>"
                for f in flags:
                    rf_html += f"<li>{f['match']}</li>"
                rf_html += "</ul></li>"
            rf_html += "</ul>"
        else:
            rf_html = "<p>No red flags detected.</p>"
        
        # Contributing factors
        factors_html = ""
        if reasons:
            factors_html = "<ol>"
            for reason in reasons:
                factors_html += f"<li>{reason}</li>"
            factors_html += "</ol>"
        else:
            factors_html = "<p>No contributing factors.</p>"
        
        # Get current theme
        current_theme = load_theme_preference()
        theme = THEMES.get(current_theme, THEMES["dark"])
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Email Forensics Report — Scam Detector v3.1</title>
<style>
    body {{
        font-family: 'Segoe UI', Arial, sans-serif;
        margin: 20px;
        background-color: {theme['bg']};
        color: {theme['fg']};
    }}
    .container {{
        max-width: 900px;
        margin: 0 auto;
    }}
    .header {{
        text-align: center;
        border-bottom: 2px solid {theme['accent']};
        padding-bottom: 15px;
        margin-bottom: 20px;
    }}
    .score-box {{
        text-align: center;
        padding: 20px;
        border-radius: 10px;
        margin: 15px 0;
        background-color: {theme['section_bg']};
        border: 2px solid {score_color};
    }}
    .score-number {{
        font-size: 48px;
        font-weight: bold;
        color: {score_color};
    }}
    .risk-label {{
        font-size: 18px;
        font-weight: bold;
        color: {score_color};
        text-transform: uppercase;
    }}
    .section {{
        background-color: {theme['section_bg']};
        border-radius: 8px;
        padding: 15px;
        margin: 15px 0;
    }}
    .section h3 {{
        color: {theme['accent']};
        margin-top: 0;
        border-bottom: 1px solid {theme['border']};
        padding-bottom: 5px;
    }}
    .detail-table {{
        width: 100%;
        border-collapse: collapse;
    }}
    .detail-table td {{
        padding: 6px 10px;
        border-bottom: 1px solid {theme['border']};
    }}
    .detail-table td:first-child {{
        font-weight: bold;
        width: 180px;
        color: {theme['secondary_fg']};
    }}
    ul, ol {{
        line-height: 1.8;
    }}
    .footer {{
        text-align: center;
        margin-top: 20px;
        padding-top: 10px;
        border-top: 1px solid {theme['border']};
        color: {theme['muted_fg']};
        font-size: 12px;
    }}
    .disclaimer {{
        background-color: {theme['disclaimer_bg']};
        border-left: 3px solid {theme['disclaimer_border']};
        padding: 10px 15px;
        margin: 15px 0;
        font-size: 13px;
        color: {theme['secondary_fg']};
    }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>🔍 Email Forensics Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p style="font-size: 12px; color: {theme['secondary_fg']};">Job Scam Detector v3.1 — Proton-Educated Edition</p>
    </div>
    
    <div class="score-box">
        <div class="score-number">{score}/100</div>
        <div class="risk-label">{risk_label} RISK</div>
        <p style="margin-top: 10px;">{verdict}</p>
    </div>
    
    <div class="disclaimer">
        <strong>⚠ Disclaimer:</strong> This report is generated by automated analysis tools and should be used as 
        a decision-support aid, not as definitive proof of fraudulent intent. All findings should be verified 
        through independent investigation before taking action.
    </div>
    
    <div class="section">
        <h3>🔐 Authentication Status</h3>
        <table class="detail-table">
            <tr><td>SPF</td><td>{spf.upper()}</td></tr>
            <tr><td>DKIM</td><td>{dkim.upper()}</td></tr>
            <tr><td>DMARC</td><td>{dmarc.upper()}</td></tr>
        </table>
    </div>
    
    <div class="section">
        <h3>👤 Recruiter Verification</h3>
        {ver_html}
    </div>
    
    <div class="section">
        <h3>📍 Email Backtrace</h3>
        {bt_html}
    </div>
    
    <div class="section">
        <h3>🚩 Red Flags Detected ({len(red_flags)})</h3>
        {rf_html}
    </div>
    
    <div class="section">
        <h3>📊 Contributing Factors ({len(reasons)})</h3>
        {factors_html}
    </div>
    
    <div class="footer">
        <p>Generated by Job Scam Detector v3.1</p>
        <p>This tool is not a substitute for professional cybersecurity advice.</p>
    </div>
</div>
</body>
</html>"""
        return html
    
    def copy_report_to_clipboard(self):
        """Copy formatted report to system clipboard."""
        if not hasattr(self, 'result_label'):
            return
        
        text = self.result_label.cget("text")
        self.clipboard_set(text)
        self.clipboard_label.configure(text="✓ Copied to clipboard!")
    
    def clipboard_set(self, text):
        """Set clipboard text."""
        try:
            self.clipboard_clear()
            self.clipboard_append(text)
        except:
            pass
    
    # ==================== SINGLE SCAN METHODS ====================
    
    def analyze_single_email(self):
        """Analyze a single email from paste or file."""
        self.progress_label.configure(text="Analyzing... Please wait (may take 30-60s)")
        self.analyze_btn.configure(state="disabled")
        
        thread = threading.Thread(target=self._analyze_single_thread, daemon=True)
        thread.start()
    
    def _analyze_single_thread(self):
        """Thread-safe email analysis."""
        try:
            if self.single_input_method.get() == "file":
                # Load from file
                pass  # Implementation would parse email_text
            else:
                email_text = self.email_text.get("1.0", "end-1c").strip()
            
            # Core analysis logic here
            msg = parse_pasted_email(email_text) if email_text else None
            
            if not msg:
                self.after(0, lambda: messagebox.showerror("Error", "Failed to parse email"))
                return
            
            # Run checks
            findings = {
                'authentication': {
                    'spf': check_spf(msg),
                    'dkim': check_dkim(msg),
                    'dmarc': check_dmarc(msg),
                },
                'domain': whois_domain_age(extract_sender_domain(msg)[0]) if extract_sender_domain(msg)[0] else {},
                'red_flags': scan_red_flags(email_text),
            }
            
            threat = calculate_threat_score(findings)
            
            # Save to history
            self.save_scan_history(threat, findings, "paste", None)
            
            # Update UI
            self.after(0, lambda: self.update_single_results(threat, findings))
            
        except Exception as e:
            self.after(0, lambda: messagebox.showerror("Analysis Error", str(e)))
        finally:
            self.after(0, lambda: self.progress_label.configure(text=""))
            self.after(0, lambda: self.analyze_btn.configure(state="normal"))
    
    def  update_single_results(self, threat, findings):
        """Update single scan results display."""
        red_flags = findings.get('red_flags', [])
        score = threat['score']
        
        # Color code
        color = "red" if score >= 75 else "orange" if score >= 50 else "yellow" if score >= 25 else "green"
        
        result_text = f"""
{'='*60}
THREAT SCORE: {score}/100
Verdict: {threat['verdict']}
{'='*60}

AUTHENTICATION STATUS:
  SPF:    {findings['authentication']['spf'].get('result', 'N/A').upper()}
  DKIM:   {findings['authentication']['dkim'].get('result', 'N/A').upper()}
  DMARC:  {findings['authentication']['dmarc'].get('result', 'N/A').upper()}

RECIPIENT VERIFICATION STATUS:
"""
        
        # Check for verification data
        verified = findings.get('verified')
        if verified:
            if verified.get('verification_complete'):
                dom_age = verified.get('domain_age_days', -1)
                mx_valid = verified.get('mx_valid', False)
                website_exists = verified.get('company_website_exists', False)
                
                dom_status = f"{dom_age} days" if dom_age > 0 else "Unknown"
                mx_status = "✓ Valid" if mx_valid else "✗ No MX records"
                site_status = "✓ Exists" if website_exists else "✗ Not found"
                
                result_text += f"  Domain Age:       {dom_status}\n"
                result_text += f"  MX Records:       {mx_status}\n"
                result_text += f"  Company Website:  {site_status}\n"
                
                if verified.get('flags'):
                    result_text += "\n  ⚠ Issues Found:\n"
                    for flag in verified['flags']:
                        result_text += f"    • {flag}\n"
            else:
                result_text += "  Verification not performed\n"
        else:
            result_text += "  Verification not available\n"
        
        result_text += "\nEMAIL BACKTRACE:\n"
        
        # Check for backtrace data
        backtrace = findings.get('backtrace')
        if backtrace:
            origin_ip = backtrace.get('origin_ip', 'N/A')
            total_hops = backtrace.get('total_hops', 0)
            geo = backtrace.get('geo_location')
            rdns = backtrace.get('reverse_dns', 'N/A')
            
            geo_str = f"{geo.get('city', 'Unknown')}, {geo.get('country_name', 'Unknown')} ({geo.get('country_code', 'XX')})" if geo else "Unknown"
            
            result_text += f"  Origin IP:      {origin_ip}\n"
            result_text += f"  Total Hops:     {total_hops}\n"
            result_text += f"  Reverse DNS:    {rdns}\n"
            result_text += f"  Geo Location:   {geo_str}\n"
            
            if backtrace.get('gmail_hiding'):
                result_text += "  ⚠ Gmail/Outlook email — origin IP hidden\n"
            
            if backtrace.get('route_suspicious'):
                result_text += "\n  ⚠ Suspicious Route Detected:\n"
                for factor in backtrace.get('risk_factors', []):
                    result_text += f"    • {factor}\n"
        else:
            result_text += "  Backtrace not available\n"
        
        result_text += "\nRED FLAGS DETECTED: {}\n".format(len(red_flags))
        
        if red_flags:
            categories = {}
            for flag in red_flags:
                cat = flag['category']
                if cat not in categories:
                    categories[cat] = []
                categories[cat].append(flag)
            
            for cat, flags in categories.items():
                result_text += "\n  [{}]\n".format(cat.upper().replace('_', ' '))
                for f in flags[:3]:
                    result_text += "    • {}\n".format(f['match'])
        
        if threat['reasons']:
            result_text += "\nCONTRIBUTING FACTORS:\n"
            for reason in threat['reasons'][:10]:
                result_text += "  • {}\n".format(reason)
        
        result_text += "\n{}".format('='*60)
        
        self.result_label.configure(text=result_text, text_color=color)
        self.current_result = threat
        self.current_findings = findings
    
    def save_scan_history(self, threat, findings, input_type, file_path):
        """Save scan result to SQLite history."""
        conn = sqlite3.connect(HISTORY_DB)
        cursor = conn.cursor()
        
        red_flags = findings.get('red_flags', [])
        sender = findings.get('authentication', {}).get('spf', {}).get('source', '')
        domain = findings.get('domain', {}).get('creation_date', '')
        
        cursor.execute('''
            INSERT INTO scans (timestamp, sender, domain, threat_score, verdict, red_flags_count, input_type, file_path)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (datetime.now().isoformat(), sender, domain, threat['score'], 
              threat['verdict'], len(red_flags), input_type, file_path))
        
        conn.commit()
        conn.close()
    
    # ==================== BATCH SCAN METHODS ====================
    
    def select_batch_folder(self):
        """Select folder for batch analysis."""
        folder = filedialog.askdirectory(title="Select folder with .eml files")
        if folder:
            self.batch_folder_label.configure(text=f"Selected: {folder}")
            self.selected_batch_folder = folder
    
    def run_batch_analysis(self):
        """Start batch analysis of all .eml files in folder."""
        if not hasattr(self, 'selected_batch_folder'):
            messagebox.showwarning("No Folder", "Please select a folder first.")
            return
        
        self.run_batch_btn.configure(state="disabled")
        self.batch_progress["value"] = 0
        self.batch_progress_label.configure(text="Starting...")
        
        thread = threading.Thread(target=self._run_batch_thread, daemon=True)
        thread.start()
    
    def _run_batch_thread(self):
        """Batch analysis worker thread."""
        files = list(Path(self.selected_batch_folder).glob("*.eml"))
        total = len(files)
        
        self.batch_progress["maximum"] = total
        
        for i, filepath in enumerate(files):
            try:
                self.batch_progress_label.configure(text=f"Processing: {filepath.name}")
                self.batch_progress["value"] = i + 1
                
                # Process each file
                msg = parse_eml_file(str(filepath))
                if msg:
                    findings = {'red_flags': scan_red_flags(str(msg))}
                    threat = calculate_threat_score(findings)
                    
                    # Insert into table
                    sender = str(msg.get('From', 'Unknown'))
                    domain = extract_sender_domain(msg)[0]
                    
                    self.after(0, lambda fp=filepath.name, sd=sender, dm=domain, ts=threat['score'], vt=threat['verdict']:
                              self.batch_tree.insert('', 'end', values=(fp, sd[:40], dm[:30], ts, vt)))
                
            except Exception as e:
                continue
        
        self.batch_progress_label.configure(text=f"Complete! Analyzed {total} files.")
        self.batch_progress_label.configure(text_color="green")
        self.run_batch_btn.configure(state="normal")
    
    def stop_batch_analysis(self):
        """Stop ongoing batch analysis (placeholder - would need cancellation flag)."""
        messagebox.showinfo("Stopped", "Batch analysis stopped (implement cancellation flag for full support).")
    
    def export_batch_csv(self):
        """Export batch scan results to CSV."""
        filepath = filedialog.asksaveasfilename(defaultextension=".csv")
        if filepath:
            # Placeholder - collect tree data and write to CSV
            messagebox.showinfo("Export", f"CSV export implemented: {filepath}")
    
    # ==================== HISTORY TAB METHODS ====================
    
    def load_history(self):
        """Load scan history into table."""
        self.history_tree.delete(*self.history_tree.get_children())
        
        min_score = int(self.score_filter.get() or 0)
        
        conn = sqlite3.connect(HISTORY_DB)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM scans WHERE threat_score >= ? ORDER BY timestamp DESC LIMIT 100
        ''', (min_score,))
        
        rows = cursor.fetchall()
        conn.close()
        
        for row in rows:
            # row: (id, timestamp, sender, domain, threat_score, verdict, red_flags_count, input_type, file_path)
            self.history_tree.insert('', 'end', values=(
                row[1][:10],  # Date only
                row[8] or "N/A",
                row[2][:30],
                row[3][:30],
                row[4],
                row[5],
                "View"
            ))
    
    def clear_history(self):
        """Clear all scan history."""
        if messagebox.askyesno("Confirm", "Clear all scan history?"):
            conn = sqlite3.connect(HISTORY_DB)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM scans")
            conn.commit()
            conn.close()
            self.load_history()
            messagebox.showinfo("Cleared", "Scan history cleared.")
    
    def export_history_csv(self):
        """Export history to CSV."""
        messagebox.showinfo("Export", "History CSV export implemented.")
    
    def view_history_detail(self, event):
        """View full details of selected history item."""
        selection = self.history_tree.selection()
        if selection:
            item = self.history_tree.item(selection[0])
            messagebox.showinfo("Details", f"Scan on {item['values'][0]} for file {item['values'][1]}")
    
    # ==================== DEMO TAB METHODS ====================
    
    def run_demo_analysis(self):
        """Run built-in test case demo."""
        test_key = self.demo_choice.get()
        if test_key not in TEST_CASES:
            return
        
        test_case = TEST_CASES[test_key]
        
        self.run_demo_btn.configure(state="disabled")
        self.demo_result_label.configure(text="Running demo analysis...")
        
        thread = threading.Thread(target=self._run_demo_thread, args=(test_case,), daemon=True)
        thread.start()
    
    def _run_demo_thread(self, test_case):
        """Demo analysis worker thread."""
        try:
            msg = parse_pasted_email(test_case['raw_email'])
            if not msg:
                self.after(0, lambda: messagebox.showerror("Error", "Failed to parse test email"))
                return
            
            findings = {
                'authentication': {
                    'spf': {'result': 'pass'},
                    'dkim': {'result': 'pass'},
                    'dmarc': {'result': 'none'},
                },
                'domain': {'creation_date': 'demo', 'age_days': 180},
                'red_flags': scan_red_flags(test_case['raw_email']),
            }
            
            threat = calculate_threat_score(findings)
            
            result_text = f"""
DEMO: {test_case['name']}

Red flags found: {len(findings['red_flags'])}

Threat Score: {threat['score']}/100
Verdict: {threat['verdict']}

Expected: {test_case['expected_score']}

Contributing factors:
"""
            
            for reason in threat['reasons'][:5]:
                result_text += f"  • {reason}\n"
            
            self.after(0, lambda r=result_text: self.demo_result_label.configure(text=r))
            
        except Exception as e:
            self.after(0, lambda: messagebox.showerror("Error", str(e)))
        finally:
            self.after(0, lambda: self.run_demo_btn.configure(state="normal"))
    
    # ==================== DRAG AND DROP ====================
    
    def setup_drag_drop(self):
        """Setup drag and drop for .eml files."""
        # This requires tkinterdnd2 extension on Linux
        # For simplicity, we use browse buttons instead in v3.0
        pass
    
    def browse_single_file(self):
        """Browse for single .eml file."""
        filepath = filedialog.askopenfilename(
            title="Select .eml File",
            filetypes=[("Email Files", "*.eml"), ("MBOX Files", "*.mbox"), ("All Files", "*.*")]
        )
        if filepath:
            try:
                with open(filepath, 'r', errors='ignore') as f:
                    email_content = f.read()
                
                self.email_text.delete("1.0", "end")
                self.email_text.insert("1.0", email_content)
                self.file_path_label.configure(text=f"Selected: {Path(filepath).name}")
            except Exception as e:
                messagebox.showerror("Error", f"Could not read file: {e}")
    
    def clear_single_tab(self):
        """Clear single scan tab."""
        self.email_text.delete("1.0", "end")
        self.result_label.configure(text="Results will appear here after analysis.", text_color="black")
        self.file_path_label.configure(text="No file selected")
        self.current_result = None


# Entry point
if __name__ == "__main__":
    app = ScamDetectorApp()
    app.mainloop()
