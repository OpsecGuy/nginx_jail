Script (mod) for Nginx which detects IP addresses that sends way too many requests and block them automatically.
It gathers date when IP sent request to web server and calculates delta time of the first connection time and last connection time and checks how many requests in that period of time was done.
Then based on requests limit it bans or not investigated IP address.


Configuration available:
- ban time
- rs limit
- minimum reqeuets to be analyzed
