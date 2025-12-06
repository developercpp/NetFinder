# 🔍 NetFinder

This project is a reconnaissance and vulnerability scanning tool designed to discover and identify potential security weaknesses in web applications. It employs various techniques, including HTTP requests and WebSocket connections, to probe a target URL and extract valuable information. The tool provides a visually appealing and informative output in the console, making it easier to understand the findings. It's designed to be a standalone tool that can also be integrated into larger security testing frameworks or CI/CD pipelines.

🚀 **Key Features**

- **HTTP Request Handling:** Sends HTTP requests with rotating user agents to simulate different browsers and analyzes responses for vulnerabilities.
- **WebSocket Communication:** Establishes WebSocket connections to test for WebSocket-related vulnerabilities and gather server information.
- **URL Parsing and Manipulation:** Parses URLs, extracts query parameters, and modifies them to test different endpoints.
- **Data Encoding/Decoding:** Uses Base64 encoding/decoding for interacting with APIs or protocols.
- **Multithreading:** Performs multiple tasks concurrently to speed up the scanning process.
- **Rich Console Output:** Displays results in a visually appealing format using tables, panels, and progress bars.
- **User Agent Rotation:** Rotates through a list of user agents to avoid being easily blocked.
- **Data Extraction:** Extracts data from HTTP responses and WebSocket messages for analysis.

🛠️ **Tech Stack**

- **Frontend:** (Console-based, using `rich` library)
    - `rich`: For creating rich text and layouts in the console.
- **Backend:**
    - `Python`
- **Core Libraries:**
    - `requests`: For making HTTP requests.
    - `websocket`: For establishing WebSocket connections.
    - `urllib.parse`: For parsing URLs.
    - `collections`: For specialized container datatypes.
    - `typing`: For type hinting.
    - `threading`: For multithreading.
    - `hashlib`: For cryptographic hashing.
    - `base64`: For base64 encoding and decoding.
    - `datetime`: For working with dates and times.
    - `json`: For handling JSON data.
    - `re`: For regular expression matching.
    - `sys`: For system-specific parameters and functions.
    - `time`: For time-related functions.
    - `random`: For generating random numbers and strings.
    - `string`: For string operations.
- **Other:**
    - `USER_AGENTS`: List of user agent strings.

📦 **Getting Started**

### Prerequisites

- Python 3.6 or higher
- `pip` package installer

### Installation

1.  Clone the repository:

    ```bash
    git clone <repository_url>
    cd <repository_directory>
    ```

2.  Install the required dependencies:

    ```bash
    pip install -r requirements.txt
    ```

    Create a `requirements.txt` file with the following content:

    ```
    requests
    websocket-client
    rich
    ```

### Running Locally

1.  Run the script:

    ```bash
    python finder.py <target_url>
    ```

    Replace `<target_url>` with the URL you want to scan.

📂 **Project Structure**

```
.
├── finder.py         # Main script for reconnaissance and vulnerability scanning
├── README.md         # This file, providing project information
└── requirements.txt  # List of Python dependencies
```


🤝 **Contributing**

Contributions are welcome! Please follow these steps:

1.  Fork the repository.
2.  Create a new branch for your feature or bug fix.
3.  Make your changes and commit them with descriptive messages.
4.  Submit a pull request.

📝 **License**

This project is licensed under the [MIT License](LICENSE) - see the `LICENSE` file for details.

📬 **Contact**

If you have any questions or suggestions, feel free to contact me on discord: aj.cpp

💖 **Thanks**

Thank you for checking out this project! Your interest and contributions are greatly appreciated.

