# WikiSummarizer - Professional Grade Application

A sophisticated Wikipedia article summarizer with AI-powered summarization, built with professional-grade Go patterns.

## 🎯 Features

### Core Functionality
- **Multi-Article Search**: Search and fetch multiple Wikipedia articles simultaneously
- **AI-Powered Summarization**: Support for both Ollama and Google Gemini
- **Server-Rendered UI**: Google-like search interface with clean design
- **Admin Dashboard**: Complete management interface
- **JWT Authentication**: Manual implementation without external libraries
- **Concurrent Processing**: Efficient parallel fetching and processing

### Technical Features
- ✅ **Generics**: Type-safe utility functions
- ✅ **Concurrency**: Goroutines and channels for parallel processing
- ✅ **Context**: Proper context usage throughout
- ✅ **Professional Logging**: Zap with structured logging and rotation
- ✅ **Configuration Management**: Viper with environment variable support
- ✅ **Database Connection Pooling**: Optimized SQLite access
- ✅ **Graceful Shutdown**: Proper cleanup on termination
- ✅ **Retry Logic**: Automatic retries with exponential backoff

## 📋 Prerequisites

- Go 1.21 or higher
- SQLite3
- Ollama (optional) or Google Gemini API key
- Make (optional, for using Makefile commands)

## 🚀 Quick Start

### 1. Run Bootstrap Script

```bash
chmod +x bootstrap.sh
./bootstrap.sh
```

### 2. Configure Application

Edit `.env` file:
```env
PORT=3000
LOG_LEVEL=info
DATABASE_PATH=./data/wikisummarizer.db
SUMMARIZER_PROVIDER=ollama
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=llama2
GEMINI_API_KEY=your_key_here
JWT_SECRET=your_secret_here
```

### 3. Install Dependencies

```bash
make deps
```

### 4. Run Tests

```bash
# Unit tests
make test-unit

# Integration tests
make test-integration

# Coverage report
make test-coverage

# Fuzz tests
make test-fuzz

# Benchmarks
make test-bench
```

### 5. Run Application

```bash
make run
```

Or build and run:
```bash
make build
./bin/wikisummarizer
```

## 🧪 Testing Strategy

This project implements comprehensive testing:

### 1. Unit Tests
- **Location**: `*_test.go` files in each package
- **Coverage**: >80% code coverage
- **Features**: Table-driven tests, parallel execution

### 2. Setup/Teardown
- Proper test initialization and cleanup
- Temporary directories and databases
- Resource cleanup with `t.Cleanup()`

### 3. Context Testing
- Context cancellation tests
- Timeout handling
- Proper context propagation

### 4. Environment Variables
- Tests with various env configurations
- Isolation between tests
- Default value validation

### 5. Viper Configuration
- Config loading from files and env vars
- Override mechanisms
- Default values

### 6. Test Data Directory
- `testdata/fixtures`: Test fixtures
- `testdata/mocks`: Mock data
- Used across multiple tests

### 7. go-cmp Library
- Detailed comparison with diff output
- Struct comparison
- Custom comparers

### 8. Table Tests
- Multiple test cases in single function
- Parallel execution with `t.Run()`
- Clear test case naming

### 9. Parallel Tests
- Tests run concurrently with `t.Parallel()`
- Thread-safe test execution
- Improved test performance

### 10. Code Coverage
- HTML coverage reports
- Per-package coverage
- Coverage threshold enforcement

### 11. Fuzz Testing
- Password hashing fuzzing
- Database input fuzzing
- Edge case discovery

### 12. Benchmarks
- Performance benchmarking
- Memory allocation tracking
- Comparison between implementations

### 13. Mocks
- HTTP mocks with `httptest`
- Database mocks
- Service mocks

### 14. Stubs
- Test doubles for external dependencies
- Controlled test environments

### 15. HTTP Testing
- `httptest.Server` for integration tests
- Request/Response validation
- Handler testing

### 16. Integration Tests
- Build tags: `//go:build integration`
- End-to-end workflows
- Real database testing

### 17. Main Function Testing
- Application startup testing
- Configuration validation
- Graceful shutdown testing

## 📁 Project Structure

```
.
├── cmd/
│   └── server/              # Application entry point
│       ├── main.go
│       └── main_test.go
├── internal/
│   ├── auth/                # JWT authentication
│   │   ├── jwt.go
│   │   └── jwt_test.go
│   ├── config/              # Configuration management
│   │   ├── config.go
│   │   └── config_test.go
│   ├── db/                  # Database layer
│   │   ├── db.go
│   │   ├── db_test.go
│   │   └── repository.go
│   ├── handlers/            # HTTP handlers
│   │   ├── admin_handler.go
│   │   ├── auth_handler.go
│   │   ├── search_handler.go
│   │   └── summary_handler.go
│   ├── middleware/          # HTTP middleware
│   │   ├── auth.go
│   │   └── logging.go
│   ├── models/              # Data models
│   │   ├── article.go
│   │   ├── settings.go
│   │   └── user.go
│   ├── routes/              # Route definitions
│   │   └── router.go
│   └── services/            # Business logic
│       └── wiki_service.go
├── pkg/
│   ├── summarizer/          # AI summarization
│   │   └── summarizer.go
│   ├── utils/               # Utility functions
│   │   ├── generic.go
│   │   ├── generic_test.go
│   │   └── logger.go
│   └── wikipedia/           # Wikipedia API client
│       ├── client.go
│       └── client_test.go
├── web/
│   ├── static/              # Static assets
│   └── templates/           # HTML templates
│       ├── admin.html
│       ├── base.html
│       ├── login.html
│       ├── search.html
│       └── summary.html
├── tests/
│   ├── integration/         # Integration tests
│   │   └── integration_test.go
│   └── unit/                # Additional unit tests
├── testdata/
│   ├── fixtures/            # Test fixtures
│   └── mocks/               # Mock data
├── configs/
│   └── config.yaml          # Configuration file
├── Makefile                 # Build automation
├── go.mod                   # Go module definition
├── go.sum                   # Go module checksums
├── .env.example             # Environment variables template
└── README.md                # This file
```

## 🔧 Advanced Features

### Generics

```go
// Map function with generics
result := utils.Map([]int{1,2,3}, func(x int) int {
    return x * 2
})

// Filter with generics
filtered := utils.Filter([]int{1,2,3,4}, func(x int) bool {
    return x % 2 == 0
})
```

### Concurrency

```go
// Concurrent page fetching
contents, err := client.GetPageContentsConcurrently(ctx, pageIDs, 3)

// Parallel map operation
results := utils.ParallelMap(input, transformFunc)
```

### Context Usage

```go
// Context with timeout
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

// Context propagation
article, err := wikiService.ProcessQuery(ctx, query)
```

## 🌐 API Endpoints

### Public Routes
- `GET /` - Search page
- `GET /summary?q=query` - Summary page
- `GET /admin/login` - Admin login

### Authentication
- `POST /api/auth/login` - User login

### Admin Routes (Protected)
- `GET /api/admin/articles` - List articles
- `DELETE /api/admin/articles/{id}` - Delete article
- `GET /api/admin/users` - List users
- `POST /api/admin/users` - Create user
- `PUT /api/admin/users/{id}` - Update user
- `DELETE /api/admin/users/{id}` - Delete user
- `GET /api/admin/settings` - Get settings
- `PUT /api/admin/settings` - Update settings

## 🔐 Default Credentials

```
Username: admin
Password: admin123
```

**⚠️ Change immediately in production!**

## 📊 Testing Commands

```bash
# Run all tests
make test

# Run with race detector
make test-unit

# Generate coverage report
make test-coverage

# Run fuzz tests
make test-fuzz

# Run benchmarks
make test-bench

# Run integration tests
make test-integration

# Format code
make fmt

# Run linter
make lint

# Run all checks
make check
```

## 🏗️ Development Workflow

1. **Create Feature Branch**
```bash
git checkout -b feature/my-feature
```

2. **Write Tests First** (TDD)
```bash
# Create test file
touch pkg/myfeature/myfeature_test.go
# Write tests
# Run tests (they should fail)
make test
```

3. **Implement Feature**
```bash
# Create implementation
touch pkg/myfeature/myfeature.go
# Implement feature
# Run tests (they should pass)
make test
```

4. **Check Coverage**
```bash
make test-coverage
# Open coverage.html
```

5. **Run All Checks**
```bash
make check
```

6. **Commit and Push**
```bash
git add .
git commit -m "feat: add my feature"
git push origin feature/my-feature
```

## 🐛 Debugging

### Enable Debug Logging

```bash
LOG_LEVEL=debug make run
```

### Check Logs

```bash
tail -f logs/app.log
```

### Database Inspection

```bash
sqlite3 data/wikisummarizer.db
.tables
SELECT * FROM users;
```

## 📈 Performance

- **Concurrent Fetching**: 3 parallel Wikipedia requests
- **Database Pool**: 25 max connections, 5 idle
- **Retry Logic**: 3 attempts with exponential backoff
- **Context Timeouts**: All operations have timeouts
- **Connection Pooling**: Reused HTTP connections

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Write tests for new features
4. Ensure all tests pass
5. Run linter and formatters
6. Submit pull request

## 📄 License

MIT License

## 🙏 Acknowledgments

- Go standard library team
- Chi router maintainers
- Zap and Viper library authors
- Wikipedia API
- Ollama and Google Gemini teams

## 📞 Support

For issues and questions:
- Open an issue on GitHub
- Check existing documentation
- Review test files for examples

---

**Built with ❤️ using Go 1.21+ and professional software engineering practices**
