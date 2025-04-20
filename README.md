
# PhantomUF - Ultra-Secure Real-time Linux Network Security System

PhantomUF is a comprehensive security solution for Linux systems that provides real-time protection against a wide range of network threats. It integrates advanced threat detection, behavioral analysis, intrusion prevention, and vulnerability scanning into a unified security framework.

## Features

- **Real-time Network Monitoring**: Continuously monitors network connections, traffic patterns, and system behavior
- **Advanced Threat Detection**: Uses multi-layered detection to identify suspicious activity including DDoS attacks, port scans, brute force attempts, and sophisticated intrusion attempts
- **Intelligent Defense**: Automatically responds to threats with context-aware countermeasures
- **Comprehensive Logging**: Maintains detailed encrypted logs of all security events for later analysis
- **Intrusion Detection System (IDS)**: Advanced pattern recognition and behavioral analysis to detect sophisticated attacks
- **Machine Learning Detection**: Uses AI algorithms to detect zero-day attacks and advanced persistent threats
- **Quantum-Resistant Encryption**: Implements post-quantum cryptography to protect against future quantum computer threats
- **Behavioral Biometrics**: Uses behavioral analysis for advanced user authentication
- **Blockchain Verification**: Secures critical security events with tamper-proof blockchain technology
- **Vulnerability Scanning**: Identifies system and network vulnerabilities with actionable remediation recommendations
- **System Hardening**: Automatically applies security hardening measures to protect the system
- **Encrypted Communication**: Secure communications with strong encryption
- **Security Scoring**: Provides a dynamic security score with recommendations for improvement
- **Modular Architecture**: Well-organized codebase for easy maintenance and extensibility
- **Command-line Interface**: Powerful CLI with extensive reporting capabilities
- **Global System Integration**: Easy installation script that integrates with systemd for automatic startup

## Installation

### Automatic Installation
The easiest way to install PhantomUF is using the provided installation script:

```
sudo ./install.sh
```

This will install PhantomUF to `/opt/phantomuf`, create a global command `phantomuf`, and set up a systemd service for automatic startup.

### Manual Installation

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/phantomuf.git
   cd phantomuf
   ```

2. Ensure you have the required dependencies:
   ```
   sudo apt update
   sudo apt install python3 python3-pip iptables netstat-nat iftop lsof
   pip3 install cryptography numpy psutil
   ```

3. Make the main script executable:
   ```
   chmod +x phantomuf.py
   ```

4. Run PhantomUF:
   ```
   sudo ./phantomuf.py start
   ```

## Usage

PhantomUF requires root privileges to function properly:

```
sudo ./phantomuf.py [command] [options]
```

### Basic Commands

- **Start PhantomUF**:
  ```
  sudo ./phantomuf.py start
  ```

- **Stop PhantomUF**:
  ```
  sudo ./phantomuf.py stop
  ```

- **Check Status**:
  ```
  sudo ./phantomuf.py status
  sudo ./phantomuf.py status --json  # Output in JSON format
  ```

- **View Logs**:
  ```
  sudo ./phantomuf.py log [--type TYPE] [--count COUNT] [--export FILENAME]
  ```

### Security Management

- **Firewall Rules**:
  ```
  sudo ./phantomuf.py rule add --ip 192.168.1.100 --action block
  sudo ./phantomuf.py rule del rule_id
  sudo ./phantomuf.py rule list
  ```

- **Vulnerability Scanning**:
  ```
  sudo ./phantomuf.py scan --type [basic|full|system|network|web|config]
  sudo ./phantomuf.py scan --type full --report json
  ```

- **Security Recommendations**:
  ```
  sudo ./phantomuf.py recommend
  sudo ./phantomuf.py recommend --apply SEC-001
  ```

### Advanced Configuration

- **Start with a specific security policy**:
  ```
  sudo ./phantomuf.py start --policy [strict|moderate|learning]
  ```

- **Disable automatic blocking**:
  ```
  sudo ./phantomuf.py start --no-auto-block
  ```

- **Disable system hardening**:
  ```
  sudo ./phantomuf.py start --no-hardening
  ```

- **Use a custom configuration file**:
  ```
  sudo ./phantomuf.py start --config myconfig.conf
  ```

## Configuration

PhantomUF uses a configuration file (phantomuf.conf) to store settings. The file is automatically created with default values if it doesn't exist.

Key configuration options:

- **policy**: Security policy level (strict, moderate, learning)
- **auto_block**: Whether to automatically block threats
- **block_duration**: How long to block IPs (in seconds)
- **whitelist_ips**: IPs that should never be blocked
- **blacklist_ips**: IPs that should always be blocked
- **ids_learning_mode**: Whether the IDS should learn normal behavior before enforcing
- **vulnerability_scan_schedule**: Schedule for automatic vulnerability scans
- **apply_system_hardening**: Whether to apply system hardening automatically
- **key_rotation_interval_days**: How often to rotate encryption keys

## Security Policies

PhantomUF supports three security policies:

1. **strict**: Highest security level, blocks all incoming traffic except explicitly allowed services
2. **moderate**: Balanced security, allows common services while blocking known dangerous ports
3. **learning**: Permissive mode that monitors traffic without blocking, useful for initial setup

## Modules

PhantomUF is built with a modular architecture:

- **FirewallManager**: Manages firewall rules using iptables
- **NetworkMonitor**: Monitors network connections and traffic
- **ThreatAnalyzer**: Analyzes network activity for potential threats
- **ThreatDefender**: Responds to identified threats with defensive measures
- **IntrusionDetectionSystem**: Advanced pattern detection and behavioral analysis
- **VulnerabilityScanner**: Scans for vulnerabilities and security misconfigurations
- **EncryptionManager**: Manages encryption for secure communications
- **LogManager**: Manages and organizes security logs
- **ConfigManager**: Manages system configuration

## Security Features

### Advanced Threat Detection

PhantomUF utilizes multiple detection methods:

- **Signature-based detection**: Matches traffic against known attack patterns
- **Anomaly-based detection**: Identifies deviations from normal behavior
- **Heuristic analysis**: Uses rule-based detection to identify suspicious patterns
- **Behavioral analysis**: Monitors system behavior for suspicious activities

### Intelligent Defense

The system responds to threats with appropriate countermeasures:

- **Automatic IP blocking**: Blocks malicious IPs at the firewall level
- **Rate limiting**: Applies rate limiting to mitigate DDoS attacks
- **Port blocking**: Closes vulnerable or targeted ports
- **Connection tracking**: Monitors and manages suspicious connections
- **Service protection**: Applies specific protections to critical services

### System Hardening

PhantomUF can automatically apply system hardening measures:

- **ASLR (Address Space Layout Randomization)**: Prevents exploitation of memory corruption vulnerabilities
- **Core dump protection**: Prevents sensitive data leakage
- **Network stack hardening**: Protects against various network attacks
- **Service hardening**: Applies secure configurations to system services

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

PhantomUF is designed as a security enhancement tool but should not be the only security measure in place. Always follow security best practices and maintain regular system updates.
