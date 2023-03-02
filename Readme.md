Script (mod) for Nginx which detects IP addresses that sends way too many requests and block them automatically.
It gathers date when IP sent request to web server and calculates delta time of the first connection time and last connection time and checks how many requests in that period of time was done.
Then based on requests limit it bans or not investigated IP address.

Configuration available:
- ban time
- rs limit
- minimum reqeuets to be analyzed

Requirements:
- Linux OS
- Enable access logs for nginx
- Provide valid path to access.log file in app.py
- Add 'include /PATH_TO_FILE/blocked_ips.conf;' to the nginx.conf (/etc/nginx/nginx.conf) in http block
