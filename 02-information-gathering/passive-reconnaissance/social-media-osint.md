# 🔍 Social Media OSINT - Open Source Intelligence from Social Platforms

**Gathering intelligence from social media platforms to support penetration testing reconnaissance**
**Location:** `02-information-gathering/passive-reconnaissance/social-media-osint.md`

## 🎯 What is Social Media OSINT?

Social Media OSINT involves collecting publicly available information from social media platforms to gather intelligence about targets, employees, and organizational structure. This passive reconnaissance technique helps penetration testers understand the human element of their target organization, identify potential attack vectors, and gather information that could be used in social engineering attacks.

Key capabilities include:
- Employee identification and profiling
- Organizational structure mapping
- Technology stack identification
- Security awareness assessment

## 📦 Installation and Setup

### Prerequisites:
- Web browser with privacy extensions
- Note-taking application
- Screenshot capability
- VPN/Proxy for anonymity (recommended)

### Essential Tools:
```bash
# Browser extensions for OSINT
# Install uBlock Origin, NoScript for privacy
# Consider using Tor browser for anonymity

# Command-line tools (optional)
apt install curl wget
pip3 install tweepy instaloader
```

### Initial Configuration:
```bash
# Create organized directory structure
mkdir -p osint-results/{linkedin,twitter,facebook,instagram,github}
mkdir -p osint-results/screenshots
mkdir -p osint-results/profiles
```

## 🔧 Basic Usage and Methodology

### Basic OSINT Workflow:
1. **Target Definition:** Identify organization and key personnel
2. **Platform Selection:** Choose relevant social media platforms
3. **Information Gathering:** Systematic data collection
4. **Analysis:** Pattern recognition and correlation
5. **Documentation:** Organized evidence collection

### General Approach:
```bash
# Start with company information
Company Name → Official Accounts → Employee Lists → Individual Profiles

# Example workflow
1. Find company LinkedIn page
2. Identify employees and their roles
3. Map organizational structure
4. Analyze individual profiles for security insights
```

## ⚙️ Platform-Specific Techniques

### LinkedIn Intelligence:
| Technique | Purpose | Information Gathered |
|-----------|---------|---------------------|
| Company Page Analysis | Org structure | Employee count, departments |
| Employee Enumeration | Personnel mapping | Names, roles, connections |
| Skills Analysis | Tech stack | Technologies used |
| Job Postings | Infrastructure | Required skills, tools |

### Twitter/X Intelligence:
| Technique | Purpose | Information Gathered |
|-----------|---------|---------------------|
| Account Discovery | Find official accounts | Company updates, announcements |
| Employee Tweets | Personal insights | Work habits, frustrations |
| Hashtag Analysis | Company culture | Internal events, projects |
| Location Data | Physical presence | Office locations, events |

### GitHub Intelligence:
| Technique | Purpose | Information Gathered |
|-----------|---------|---------------------|
| Organization Repos | Code analysis | Technologies, frameworks |
| Employee Profiles | Development practices | Coding patterns, skills |
| Commit Analysis | Development timeline | Active projects, contributors |
| Configuration Files | Infrastructure | Deployment details, configs |

## 🧪 Real Lab Examples

### Example 1: LinkedIn Employee Enumeration
```bash
# Manual process using LinkedIn
1. Navigate to target company LinkedIn page
2. Click on "See all X employees on LinkedIn"
3. Document key personnel:
   - IT Administrator: John Smith
   - Security Manager: Jane Doe
   - Developer: Mike Johnson

# Information gathered:
Output: 25 employees identified
- 3 IT staff members
- 2 security personnel  
- 5 developers
- Technologies mentioned: Windows Server, Cisco, Python
```

### Example 2: Twitter Intelligence Gathering
```bash
# Search techniques
1. Search: "from:@company_handle"
2. Search: "company_name employees"
3. Search: "#companyname OR @companyname"

# Results analysis
Output: Recent tweets reveal:
- Planned system maintenance next week
- New employee onboarding (potential targets)
- Frustration with VPN connectivity issues
- Company using Microsoft Teams for communication
```

### Example 3: GitHub Repository Analysis
```bash
# Repository investigation
1. Search for organization on GitHub
2. Analyze public repositories
3. Check commit messages and contributors

# Key findings
Output: GitHub analysis reveals:
- Web application built with PHP/MySQL
- Development server configs in repo
- Database connection strings (sanitized but showing structure)
- 3 active developers with commit access
```

## 🎯 eJPT Exam Focus

### Essential Skills for eJPT:
- **Employee identification (25%)** - Critical for social engineering prep
- **Technology stack discovery (20%)** - Helps focus technical attacks
- **Organizational mapping (15%)** - Understanding target structure
- **Security awareness assessment (10%)** - Identifying weak links

### Critical Techniques to Master:
```bash
# Must-know approaches for exam
linkedin_employee_enumeration    # Essential for personnel mapping
github_repository_analysis       # Technology identification
twitter_information_gathering    # Real-time intelligence
facebook_company_page_analysis   # Additional organizational intel
```

### eJPT Exam Scenarios:
1. **Employee Enumeration Scenario:** 
   - Required skills: LinkedIn navigation, profile analysis
   - Expected outcome: List of key IT personnel
   - Success criteria: Identify at least 3 technical staff members

2. **Technology Discovery Scenario:**
   - Required skills: GitHub analysis, job posting review
   - Expected outcome: Technology stack identification
   - Success criteria: Identify primary technologies and frameworks

### Exam Tips and Tricks:
- **Tip 1:** Always check multiple platforms for cross-validation
- **Tip 2:** Focus on IT and security personnel during employee enumeration
- **Tip 3:** Document everything with screenshots for evidence
- **Tip 4:** Look for patterns in posting times to understand work schedules

### Common eJPT Questions:
- Identify employees with administrative privileges
- Determine what technologies the company uses
- Find information that could be used for social engineering

## ⚠️ Common Issues & Troubleshooting

### Issue 1: Limited LinkedIn Access Without Account
**Problem:** LinkedIn limits visibility of employee lists for non-members
**Cause:** Platform privacy restrictions
**Solution:**
```bash
# Alternative approaches
1. Use Google search: site:linkedin.com "company name" "employee"
2. Cross-reference with other platforms
3. Use cached/archived versions
```

### Issue 2: Privacy Settings Blocking Information
**Problem:** Individual profiles set to private
**Solution:**
```bash
# Focus on public information only
1. Company pages (usually public)
2. Public posts and interactions
3. Professional associations and groups
```

### Issue 3: Too Much Information to Process
**Problem:** Information overload from large organizations
**Optimization:**
```bash
# Prioritize target selection
1. Focus on IT/Security departments
2. Prioritize senior roles and administrators
3. Look for recently hired employees (potential security gaps)
```

## 🔗 Integration with Other Tools

### Primary Integration: Social Media OSINT → Google Dorking
```bash
# Use discovered information for targeted searches
employee_name + company_name + "password reset"
technology_stack + company_name + "configuration"
employee_email + "login" + "credentials"

# Example workflow
# Step 1: LinkedIn identifies "John Smith, IT Admin"
# Step 2: Google dork: "John Smith" site:company.com
# Step 3: Find additional information about John's responsibilities
```

### Secondary Integration: OSINT → Shodan/Technical Reconnaissance
```bash
# Use organizational intelligence for technical searches
company_name + server_type_discovered_on_linkedin
office_locations_from_social_media → shodan_searches
technology_stack_from_github → vulnerability_research
```

### Advanced Workflows:
```bash
# Complete reconnaissance chain
social_media_osint → employee_list → email_enumeration → phishing_targets
github_analysis → technology_discovery → vulnerability_scanning → exploit_selection
```

## 📝 Documentation and Reporting

### Evidence Collection Requirements:
1. **Screenshots:** Profile pages, company information, technology mentions
2. **Employee Lists:** Names, roles, contact information, social media handles
3. **Technology Stack:** Frameworks, tools, services identified
4. **Organizational Structure:** Departments, hierarchies, key personnel

### Report Template Structure:
```markdown
## Social Media OSINT Results

### Target Information
- Organization: company_name
- Analysis Date: timestamp
- Platforms Analyzed: LinkedIn, Twitter, GitHub, Facebook

### Personnel Intelligence
#### Key IT Staff Identified:
- Name: John Smith, Role: IT Administrator, LinkedIn: profile_url
- Name: Jane Doe, Role: Security Manager, LinkedIn: profile_url

#### Organizational Structure:
- IT Department Size: X employees
- Security Team: Y members
- Development Team: Z developers

### Technology Intelligence
#### Technology Stack Identified:
- Operating Systems: Windows Server 2019, Ubuntu Linux
- Applications: Microsoft Exchange, Cisco ASA
- Development: PHP, MySQL, Apache
- Cloud Services: Office 365, AWS

### Security Insights
#### Potential Attack Vectors:
- Employee frustrations with VPN (potential bypass attempts)
- Recent hires (less security awareness)
- Public configuration details in GitHub

#### Social Engineering Opportunities:
- Company events for pretexting
- Employee interests for spear phishing
- Organizational relationships for impersonation
```

### Automation and Organization:
```bash
# Directory structure for organized collection
osint-results/
├── linkedin/
│   ├── company-profile.pdf
│   ├── employee-list.txt
│   └── screenshots/
├── twitter/
│   ├── company-tweets.txt
│   └── employee-tweets.txt
├── github/
│   ├── repository-analysis.txt
│   └── technology-stack.txt
└── summary-report.md
```

## 📚 Additional Resources

### Official Documentation:
- LinkedIn Learning: OSINT fundamentals
- Twitter Advanced Search: search.twitter.com
- GitHub Search Documentation: docs.github.com/search

### Learning Resources:
- OSINT Framework: osintframework.com
- IntelTechniques: inteltechniques.com
- Bellingcat Online Investigation Toolkit

### Legal and Ethical Considerations:
- Always respect platform terms of service
- Only collect publicly available information
- Maintain professional boundaries
- Document sources for evidence integrity

### Related Tools:
- Maltego: Visual link analysis and data mining
- theHarvester: Email and subdomain enumeration
- Recon-ng: Automated reconnaissance framework
