import streamlit as st
import random
import string
import math
import re
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import json
import os
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

st.set_page_config(
    page_title="Password Generator",
    page_icon="🔐",
    layout="wide"
)

st.title("🔐 Password Generator & Strength Checker")
st.markdown("Generate uncrackable passwords and analyze "
            "the strength of any password instantly.")
st.markdown("---")

# Password analysis function
def analyze_password(password):
    length      = len(password)
    has_upper   = bool(re.search(r'[A-Z]', password))
    has_lower   = bool(re.search(r'[a-z]', password))
    has_digit   = bool(re.search(r'\d', password))
    has_special = bool(re.search(
        r'[!@#$%^&*(),.?":{}|<>]', password))
    has_space   = ' ' in password

    # Character pool size
    pool = 0
    if has_lower:   pool += 26
    if has_upper:   pool += 26
    if has_digit:   pool += 10
    if has_special: pool += 32

    # Entropy calculation
    entropy = length * math.log2(pool) if pool > 0 else 0

    # Crack time estimation
    guesses_per_sec = 1e12  # 1 trillion/sec
    combinations    = pool ** length if pool > 0 else 1
    seconds         = combinations / guesses_per_sec

    if seconds < 1:
        crack_time = "Instantly"
    elif seconds < 60:
        crack_time = f"{seconds:.1f} seconds"
    elif seconds < 3600:
        crack_time = f"{seconds/60:.1f} minutes"
    elif seconds < 86400:
        crack_time = f"{seconds/3600:.1f} hours"
    elif seconds < 31536000:
        crack_time = f"{seconds/86400:.1f} days"
    elif seconds < 3.15e9:
        crack_time = f"{seconds/31536000:.1f} years"
    elif seconds < 3.15e12:
        crack_time = f"{seconds/3.15e9:.1f} thousand years"
    elif seconds < 3.15e15:
        crack_time = f"{seconds/3.15e12:.1f} million years"
    else:
        crack_time = "Billions of years 🔒"

    # Score
    score = 0
    if length >= 8:   score += 1
    if length >= 12:  score += 1
    if length >= 16:  score += 1
    if has_upper:     score += 1
    if has_lower:     score += 1
    if has_digit:     score += 1
    if has_special:   score += 1
    if length >= 20:  score += 1

    if score <= 2:
        strength = "Very Weak"
        color    = "#e74c3c"
    elif score <= 4:
        strength = "Weak"
        color    = "#e67e22"
    elif score <= 5:
        strength = "Moderate"
        color    = "#f39c12"
    elif score <= 6:
        strength = "Strong"
        color    = "#2ecc71"
    else:
        strength = "Very Strong"
        color    = "#27ae60"

    # Common patterns check
    warnings_list = []
    common = [
        "password", "123456", "qwerty",
        "abc123", "letmein", "admin",
        "welcome", "monkey", "dragon"
    ]
    if password.lower() in common:
        warnings_list.append(
            "⚠️ This is one of the most common passwords!")
    if re.search(r'(.)\1{2,}', password):
        warnings_list.append(
            "⚠️ Contains repeated characters (aaa, 111)")
    if re.search(r'(012|123|234|345|456|'
                 r'567|678|789|890)', password):
        warnings_list.append(
            "⚠️ Contains sequential numbers")
    if re.search(r'(abc|bcd|cde|def|efg|'
                 r'fgh|ghi|hij)', password.lower()):
        warnings_list.append(
            "⚠️ Contains sequential letters")

    return {
        'length':      length,
        'strength':    strength,
        'color':       color,
        'score':       score,
        'entropy':     round(entropy, 1),
        'crack_time':  crack_time,
        'has_upper':   has_upper,
        'has_lower':   has_lower,
        'has_digit':   has_digit,
        'has_special': has_special,
        'warnings':    warnings_list,
        'pool':        pool
    }

# Password generator
def generate_password(length, use_upper, use_lower,
                      use_digits, use_special,
                      exclude_ambiguous):
    chars = ""
    if use_lower:
        chars += string.ascii_lowercase
    if use_upper:
        chars += string.ascii_uppercase
    if use_digits:
        chars += string.digits
    if use_special:
        chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"

    if exclude_ambiguous:
        ambiguous = "0O1lI|`'"
        chars = ''.join(
            c for c in chars
            if c not in ambiguous
        )

    if not chars:
        return "Please select at least one character type"

    # Ensure at least one of each type
    password = []
    if use_lower and string.ascii_lowercase:
        lc = string.ascii_lowercase
        if exclude_ambiguous:
            lc = ''.join(
                c for c in lc
                if c not in "l")
        password.append(random.choice(lc))
    if use_upper and string.ascii_uppercase:
        uc = string.ascii_uppercase
        if exclude_ambiguous:
            uc = ''.join(
                c for c in uc
                if c not in "OI")
        password.append(random.choice(uc))
    if use_digits and string.digits:
        dg = string.digits
        if exclude_ambiguous:
            dg = ''.join(
                c for c in dg
                if c not in "01")
        password.append(random.choice(dg))
    if use_special:
        password.append(
            random.choice("!@#$%^&*()_+-="))

    while len(password) < length:
        password.append(random.choice(chars))

    random.shuffle(password)
    return ''.join(password)

# Tabs
tab1, tab2, tab3, tab4 = st.tabs([
    "🔑 Generator",
    "🔍 Strength Checker",
    "📊 Analysis",
    "💡 Tips"
])

# Tab 1 — Generator
with tab1:
    st.markdown("### Generate a Secure Password")

    col1, col2 = st.columns([1, 1])

    with col1:
        length = st.slider(
            "Password length:", 8, 64, 16)
        use_upper   = st.checkbox(
            "Uppercase (A-Z)", value=True)
        use_lower   = st.checkbox(
            "Lowercase (a-z)", value=True)
        use_digits  = st.checkbox(
            "Numbers (0-9)", value=True)
        use_special = st.checkbox(
            "Special chars (!@#$)", value=True)
        exclude_amb = st.checkbox(
            "Exclude ambiguous (0,O,1,l,I)",
            value=False)
        num_passwords = st.slider(
            "Generate how many?", 1, 10, 5)

    with col2:
        if st.button("🔑 Generate Passwords",
                     type="primary"):
            passwords = []
            for _ in range(num_passwords):
                pwd = generate_password(
                    length, use_upper, use_lower,
                    use_digits, use_special,
                    exclude_amb
                )
                analysis = analyze_password(pwd)
                passwords.append({
                    'Password':  pwd,
                    'Strength':  analysis['strength'],
                    'Entropy':   f"{analysis['entropy']} bits",
                    'Crack Time':analysis['crack_time']
                })

            df_pwd = pd.DataFrame(passwords)
            st.dataframe(df_pwd,
                         use_container_width=True,
                         hide_index=True)

            # Show best password
            best = passwords[-1]['Password']
            st.markdown("### 🏆 Recommended Password")
            st.code(best, language=None)

            analysis = analyze_password(best)
            c1, c2, c3 = st.columns(3)
            c1.metric("Strength",
                      analysis['strength'])
            c2.metric("Entropy",
                      f"{analysis['entropy']} bits")
            c3.metric("Crack Time",
                      analysis['crack_time'])

            st.download_button(
                "⬇️ Download Passwords",
                df_pwd.to_csv(index=False),
                "passwords.csv",
                "text/csv"
            )

        st.markdown("### 🎲 Memorable Passphrase")
        words = [
            "Tiger", "Mountain", "River", "Storm",
            "Dragon", "Phoenix", "Galaxy", "Thunder",
            "Ocean", "Forest", "Lightning", "Crystal",
            "Shadow", "Falcon", "Warrior", "Legend"
        ]
        if st.button("Generate Passphrase"):
            phrase_words = random.sample(words, 4)
            number       = random.randint(10, 99)
            special      = random.choice("!@#$")
            passphrase   = (
                ''.join(phrase_words) +
                str(number) + special
            )
            st.code(passphrase, language=None)
            analysis = analyze_password(passphrase)
            st.success(
                f"Strength: {analysis['strength']} | "
                f"Crack time: {analysis['crack_time']}"
            )

# Tab 2 — Strength Checker
with tab2:
    st.markdown("### Check Any Password's Strength")
    st.warning("⚠️ Never enter your real passwords "
               "into any website. This runs locally.")

    password_input = st.text_input(
        "Enter password to analyze:",
        type="password",
        placeholder="Type any password..."
    )

    show_password = st.checkbox("Show password")
    if show_password and password_input:
        st.code(password_input, language=None)

    if password_input:
        a = analyze_password(password_input)

        st.markdown("---")
        st.markdown(
            f"<h2 style='text-align:center; "
            f"color:{a['color']}'>"
            f"{'⭐' * min(a['score'], 5)} "
            f"{a['strength']}</h2>",
            unsafe_allow_html=True
        )

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Length",     a['length'])
        c2.metric("Entropy",    f"{a['entropy']} bits")
        c3.metric("Score",      f"{a['score']}/8")
        c4.metric("Crack Time", a['crack_time'])

        # Strength bar
        fig, ax = plt.subplots(figsize=(10, 1.5))
        score_pct = a['score'] / 8 * 100
        ax.barh([''], [score_pct],
                color=a['color'], height=0.5)
        ax.barh([''], [100 - score_pct],
                left=[score_pct],
                color='#ecf0f1', height=0.5)
        ax.set_xlim(0, 100)
        ax.set_title(
            f"Password Strength: "
            f"{score_pct:.0f}%",
            fontsize=12
        )
        ax.axis('off')
        plt.tight_layout()
        st.pyplot(fig)

        # Checklist
        st.markdown("### ✅ Security Checklist")
        checks = [
            (a['length'] >= 8,
             "At least 8 characters"),
            (a['length'] >= 12,
             "At least 12 characters"),
            (a['length'] >= 16,
             "At least 16 characters"),
            (a['has_upper'],
             "Contains uppercase letters"),
            (a['has_lower'],
             "Contains lowercase letters"),
            (a['has_digit'],
             "Contains numbers"),
            (a['has_special'],
             "Contains special characters"),
            (a['entropy'] >= 60,
             "High entropy (60+ bits)")
        ]
        for passed, desc in checks:
            icon = "✅" if passed else "❌"
            st.markdown(f"{icon} {desc}")

        if a['warnings']:
            st.markdown("### ⚠️ Warnings")
            for w in a['warnings']:
                st.error(w)

# Tab 3 — Analysis
with tab3:
    st.markdown("### 📊 Password Length vs Security")

    lengths  = list(range(6, 33))
    entropies = []
    crack_times_label = []

    for l in lengths:
        pool    = 26 + 26 + 10 + 32
        entropy = l * math.log2(pool)
        entropies.append(round(entropy, 1))

        guesses = 1e12
        combos  = pool ** l
        secs    = combos / guesses
        if secs < 60:
            crack_times_label.append("Seconds")
        elif secs < 3600:
            crack_times_label.append("Minutes")
        elif secs < 86400:
            crack_times_label.append("Hours")
        elif secs < 31536000:
            crack_times_label.append("Days")
        elif secs < 3.15e9:
            crack_times_label.append("Years")
        elif secs < 3.15e12:
            crack_times_label.append("Thousands yrs")
        elif secs < 3.15e15:
            crack_times_label.append("Millions yrs")
        else:
            crack_times_label.append("Billions yrs")

    fig, ax = plt.subplots(figsize=(12, 5))
    colors  = ['#e74c3c' if e < 40 else
               '#f39c12' if e < 60 else
               '#2ecc71'
               for e in entropies]
    ax.bar(lengths, entropies,
           color=colors, edgecolor='black')
    ax.axhline(y=40, color='#e74c3c',
               linestyle='--', alpha=0.7,
               label='Minimum (40 bits)')
    ax.axhline(y=60, color='#f39c12',
               linestyle='--', alpha=0.7,
               label='Good (60 bits)')
    ax.axhline(y=80, color='#2ecc71',
               linestyle='--', alpha=0.7,
               label='Excellent (80 bits)')
    ax.set_title(
        'Password Entropy by Length '
        '(All character types)',
        fontsize=14
    )
    ax.set_xlabel('Password Length (characters)')
    ax.set_ylabel('Entropy (bits)')
    ax.legend(fontsize=10)
    plt.tight_layout()
    st.pyplot(fig)

    # Table
    df_analysis = pd.DataFrame({
        'Length':     lengths,
        'Entropy':    entropies,
        'Crack Time': crack_times_label
    })
    st.dataframe(df_analysis,
                 use_container_width=True,
                 hide_index=True)

# Tab 4 — Tips
with tab4:
    st.markdown("### 💡 Password Security Guide")

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("#### ✅ DO")
        st.success("""
        - Use at least 16 characters
        - Mix uppercase, lowercase, numbers, symbols
        - Use a different password for every account
        - Use a password manager (Bitwarden is free)
        - Enable two-factor authentication everywhere
        - Use passphrases for memorable passwords
        - Change passwords after any data breach
        """)

    with col2:
        st.markdown("#### ❌ DON'T")
        st.error("""
        - Don't use personal info (name, birthday)
        - Don't reuse passwords across sites
        - Don't use dictionary words alone
        - Don't use keyboard patterns (qwerty, 12345)
        - Don't share passwords via chat or email
        - Don't store passwords in plain text files
        - Don't use passwords shorter than 12 chars
        """)

    st.markdown("### 🔒 How Passwords Get Cracked")
    methods = pd.DataFrame({
        'Method':      [
            'Dictionary Attack',
            'Brute Force',
            'Rainbow Tables',
            'Phishing',
            'Data Breach'
        ],
        'Description': [
            'Tries common words and phrases',
            'Tries every possible combination',
            'Pre-computed hash lookups',
            'Tricks you into giving it away',
            'Stolen from hacked websites'
        ],
        'Defense': [
            'Avoid real words',
            'Use long passwords (16+ chars)',
            'Use salted hashes (done by websites)',
            'Never click suspicious links',
            'Use unique passwords everywhere'
        ]
    })
    st.dataframe(methods,
                 use_container_width=True,
                 hide_index=True)

st.markdown("---")
st.markdown(
    "Built by **Jyotiraditya** | "
    "Password Generator & Security Checker | "
    "Your passwords are never stored or transmitted"
)