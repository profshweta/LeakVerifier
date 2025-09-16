# SDK Leak Detection Dashboard  

This project is a **Flask-based web dashboard** that works with **mitmproxy** to detect and analyze data leaks from Android apps.   
The dashboard updates in real-time while mitmproxy is running and clears logs when mitmproxy stops.  
## Project Created By  
**Shubhangi Yadav**   
---

## Tools & Dependencies  

- **Python 3.8+**  
- **Flask** (for web dashboard)  
- **mitmproxy** (for capturing app traffic)  
- **json** (for structured logging)  
- **re** (for regex-based PII/data leak detection)  
- **gzip** (for decoding compressed data)  

---

## Setup Instructions  

1. Clone or download this project.  
2. Install the required Python dependencies:  

   ```bash
   pip install flask mitmproxy
   ```



3. Place your `sdk_sniffer.py` mitmproxy addon script inside the project folder.  
4. Ensure you have `app.py` (Flask server) and `sdk_logs.json` (auto-created) in the same folder.  

---

##  Running the Project  

1. Start mitmproxy with the SDK sniffer addon:  

   ```bash
   mitmproxy -s sdk_sniffer.py
   ```

   - This will capture app traffic and log SDK usage into `sdk_logs.json`.  
   - Logs are cleared automatically when mitmproxy starts/stops.  

2. In a new terminal, start the Flask web dashboard:  

   ```bash
   python app.py
   ```

3. Open your browser and visit:  

   ```
   http://127.0.0.1:5000
   ```

 