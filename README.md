# SmartHire - AI-Powered Recruitment System

## Overview

SmartHire is an intelligent recruitment platform that leverages artificial intelligence to streamline the hiring process. The system automates resume parsing, conducts AI-powered interviews, and provides comprehensive candidate evaluation tools.

## Features

### 🤖 AI Interviewer
- Automated interview generation based on job requirements
- Real-time candidate assessment
- Intelligent question adaptation
- Comprehensive interview analytics

### 📄 Resume Parser
- Automatic resume extraction and analysis
- Skill identification and matching
- Experience level assessment
- Structured data extraction

### 📊 Dashboard
- Candidate tracking and management
- Interview scheduling and monitoring
- Performance analytics and reporting
- Real-time status updates

## Project Structure

```
SmartHire/
├── app.py              # Main application entry point
├── ai_interviewer.py   # AI interview generation and management
├── resume_parser.py    # Resume parsing and analysis
├── dashboard.py        # Dashboard functionality
├── models/             # Database models
├── templates/          # HTML templates
├── static/             # Static assets (CSS, JS, images)
├── migrations/         # Database migration files
├── instance/           # Instance-specific files
├── .env               # Environment variables
├── requirements.txt    # Python dependencies
├── init_db.py         # Database initialization
└── reset_db.py        # Database reset utilities
```

## Installation

### Prerequisites
- Python 3.8+
- pip package manager
- Virtual environment (recommended)

### Setup Instructions

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd SmartHire
   ```

2. **Create and activate virtual environment**
   ```bash
   python -m venv venv
   # Windows
   venv\Scripts\activate
   # macOS/Linux
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables**
   - Copy `.env.example` to `.env` (if available)
   - Configure necessary environment variables:
     - Database connection strings
     - API keys for AI services
     - Security keys

5. **Initialize database**
   ```bash
   python init_db.py
   ```

6. **Run the application**
   ```bash
   python app.py
   ```

## Configuration

### Environment Variables

Key environment variables to configure in `.env`:

```env
# Database Configuration
DATABASE_URL=sqlite:///smarthire.db

# AI Service Configuration
OPENAI_API_KEY=your_openai_api_key
AI_MODEL=gpt-3.5-turbo

# Security
SECRET_KEY=your_secret_key
FLASK_ENV=development

# File Upload Configuration
UPLOAD_FOLDER=uploads
MAX_CONTENT_LENGTH=16777216
```

### Database Setup

The application uses SQLAlchemy for database management. Supported databases:
- SQLite (default)
- PostgreSQL
- MySQL

To use PostgreSQL or MySQL, update the `DATABASE_URL` in your `.env` file.

## Usage

### For Recruiters

1. **Create Job Postings**: Define roles, requirements, and interview criteria
2. **Upload Resumes**: Batch upload candidate resumes for parsing
3. **Schedule Interviews**: Set up AI-powered interviews with candidates
4. **Review Results**: Access comprehensive candidate evaluations and reports

### For Candidates

1. **Apply for Positions**: Submit resumes and complete application forms
2. **Take AI Interviews**: Participate in automated interview sessions
3. **Receive Feedback**: Get insights about interview performance

## API Documentation

### Core Endpoints

- `POST /api/parse-resume` - Parse and analyze uploaded resumes
- `POST /api/generate-interview` - Create AI-powered interview questions
- `GET /api/candidates` - Retrieve candidate information
- `POST /api/interview/submit` - Submit interview responses

### Authentication

The system uses token-based authentication. Include API tokens in request headers:
```
Authorization: Bearer <your_api_token>
```

## Development

### Running Tests

```bash
python -m pytest tests/
```

### Code Style

The project follows PEP 8 guidelines. Use flake8 for linting:
```bash
flake8 .
```

### Database Migrations

Create new migrations:
```bash
flask db migrate -m "description"
```

Apply migrations:
```bash
flask db upgrade
```

## Deployment

### Docker Deployment

1. **Build Docker image**
   ```bash
   docker build -t smarthire .
   ```

2. **Run container**
   ```bash
   docker run -p 5000:5000 smarthire
   ```

### Production Considerations

- Use HTTPS in production
- Configure proper database backup strategies
- Set up monitoring and logging
- Implement rate limiting for API endpoints
- Regular security updates

## Security

- Input validation and sanitization
- SQL injection prevention through ORM
- CSRF protection enabled
- Secure file upload handling
- Environment-based configuration

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions:
- Create an issue in the repository
- Contact the development team
- Check the documentation for common solutions

## Changelog

### Version 1.0.0
- Initial release
- Basic resume parsing functionality
- AI interviewer integration
- Dashboard implementation
- Database setup and migrations

---

**Note**: This documentation is for the SmartHire AI recruitment system. Ensure all environment variables are properly configured before running the application.
