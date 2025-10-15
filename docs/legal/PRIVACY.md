# Privacy Policy

## 🔒 REVENG Privacy Policy

This document describes how REVENG handles user data and privacy.

## 📋 Data Collection

### What We Collect

REVENG is designed to be privacy-focused and collects minimal data:

- **No Personal Information**: We do not collect personal information
- **No Analysis Data**: Analysis results are not transmitted or stored
- **No Usage Analytics**: No user behavior tracking
- **No File Content**: Binary files are processed locally only

### What We Don't Collect

- **Binary Files**: Your analysis files never leave your system
- **Analysis Results**: Generated reports stay on your machine
- **Personal Data**: No names, emails, or personal information
- **Usage Patterns**: No tracking of how you use REVENG
- **Network Data**: No monitoring of your network activity

## 🏠 Local Processing

### Privacy by Design

REVENG is designed with privacy in mind:

- **Local Analysis**: All analysis happens on your machine
- **No Cloud Processing**: No data is sent to external servers
- **Offline Capable**: Works without internet connection
- **Data Control**: You maintain complete control over your data

### AI Services (Optional)

When using AI features, you can choose your AI provider:

- **Ollama**: Completely local AI processing
- **Anthropic**: Secure API with data handling policies
- **OpenAI**: API with data usage policies
- **Custom**: Use your own AI services

## 🔐 Data Security

### File Handling

- **Temporary Storage**: Analysis files are stored temporarily
- **Automatic Cleanup**: Files are automatically deleted after analysis
- **Secure Deletion**: Files are securely overwritten before deletion
- **No Persistence**: No analysis data is permanently stored

### Network Security

- **Encrypted Communications**: All external communications use TLS
- **API Key Protection**: API keys are stored securely
- **No Data Transmission**: Analysis data is not transmitted
- **Secure Defaults**: Secure configuration by default

## 🛠️ Configuration

### Privacy Settings

```yaml
# .reveng/privacy.yaml
privacy:
  local_processing: true
  auto_cleanup: true
  secure_deletion: true
  no_telemetry: true
  ai_provider: "ollama"  # Use local AI
  network_timeout: 30
```

### Environment Variables

```bash
# Privacy-related environment variables
export REVENG_PRIVACY_MODE=true
export REVENG_NO_TELEMETRY=true
export REVENG_AUTO_CLEANUP=true
export REVENG_SECURE_DELETION=true
```

## 🌐 AI Services Privacy

### Ollama (Recommended)

- **Completely Local**: No data leaves your machine
- **No Internet Required**: Works offline
- **Full Control**: You control all data processing
- **Privacy First**: Designed for privacy

### Anthropic

- **Data Handling**: Follows Anthropic's data policies
- **No Training**: Data not used for model training
- **Secure API**: Encrypted communications
- **Data Retention**: Minimal data retention

### OpenAI

- **Data Usage**: Follows OpenAI's data usage policies
- **API Security**: Secure API communications
- **Data Retention**: Limited data retention
- **Usage Policies**: Subject to OpenAI's terms

## 🔍 Data Transparency

### What Happens to Your Data

1. **Upload**: Binary files are stored temporarily on your machine
2. **Analysis**: Processing happens locally
3. **Results**: Generated reports stay on your machine
4. **Cleanup**: All temporary files are automatically deleted
5. **No Transmission**: No data is sent to external servers

### Logging

- **No Personal Data**: Logs contain no personal information
- **Technical Only**: Only technical information is logged
- **Local Storage**: Logs are stored locally only
- **Automatic Rotation**: Logs are automatically rotated and deleted

## 🛡️ Privacy Controls

### User Controls

- **Data Deletion**: Delete all analysis data at any time
- **AI Provider Choice**: Choose your AI provider
- **Network Control**: Control network access
- **File Permissions**: Control file access permissions

### Administrative Controls

- **Audit Logging**: Track system access and changes
- **Access Control**: Control who can access the system
- **Data Retention**: Control how long data is kept
- **Backup Security**: Secure backup procedures

## 📊 Compliance

### Data Protection Regulations

REVENG is designed to comply with:

- **GDPR**: European General Data Protection Regulation
- **CCPA**: California Consumer Privacy Act
- **PIPEDA**: Personal Information Protection and Electronic Documents Act
- **Other Privacy Laws**: Designed to be compliant with privacy regulations

### Privacy Principles

- **Minimal Collection**: Collect only necessary data
- **Purpose Limitation**: Use data only for intended purposes
- **Data Minimization**: Keep data only as long as necessary
- **Transparency**: Clear information about data handling
- **User Control**: Users control their data

## 🔧 Privacy Tools

### Data Cleanup

```bash
# Clean all analysis data
python scripts/clean_outputs.py --all

# Clean specific analysis
python scripts/clean_outputs.py --analysis analysis_123

# Secure deletion
python scripts/clean_outputs.py --secure
```

### Privacy Verification

```bash
# Verify privacy settings
python scripts/verify_privacy.py

# Check data collection
python scripts/check_privacy.py

# Audit data handling
python scripts/audit_privacy.py
```

## 📞 Privacy Concerns

### Reporting Privacy Issues

If you have privacy concerns:

1. **Email**: privacy@reveng-toolkit.org
2. **GitHub**: [Privacy Issues](https://github.com/oimiragieo/reveng-main/issues)
3. **Discussions**: [Privacy Discussions](https://github.com/oimiragieo/reveng-main/discussions)

### Privacy Questions

- **Data Handling**: How is my data handled?
- **AI Services**: What data is sent to AI services?
- **Storage**: Where is my data stored?
- **Deletion**: How is my data deleted?

## 📚 Related Documentation

- **[Security Policy](SECURITY.md)** - Security practices
- **[Installation Guide](INSTALLATION.md)** - Privacy-focused installation
- **[User Guide](docs/USER_GUIDE.md)** - Privacy best practices
- **[Configuration](docs/CONFIGURATION.md)** - Privacy settings

## 🔄 Policy Updates

### Changes to This Policy

- **Notification**: Users will be notified of significant changes
- **Version Control**: Policy versions are tracked
- **Transparency**: Changes are clearly documented
- **User Rights**: Users maintain control over their data

### Contact for Updates

- **Email**: privacy@reveng-toolkit.org
- **GitHub**: [Policy Updates](https://github.com/oimiragieo/reveng-main/discussions)
- **Website**: [Privacy Policy](https://reveng-toolkit.org/privacy)

---

**Privacy Policy** - Protecting your privacy and data
