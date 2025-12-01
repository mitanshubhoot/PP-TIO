# PP-TIO: Elevator Pitch

1. Imagine if two companies could compare their secret threat lists to find common hackers, without ever revealing a single IP address to each other. That's what my project does.

2. Cyberattacks are global, but defense is isolated. Companies *need* to share threat intelligence to stay safe, but they *can't* because of privacy laws like GDPR and fear of leaking business secrets.

3. I built **PP-TIO** (Privacy-Preserving Threat Intelligence Overlap). It uses **Homomorphic Encryption** and **Bloom Filters** to let two parties, like ISPs or banks, mathematically calculate exactly how many threats they share, without **ever** decrypting the data.

4. It allows for secure collaboration: you find out *if* you're being attacked by the same group, without revealing *who* your customers are.


- **First**, I compress threat data (IPs, URLs) into **Bloom Filters**, efficient probabilistic data structures.
- **Then**, I encrypt these filters using the **BFV Homomorphic Encryption** scheme.

5. This allows us to perform logical AND operations directly on the **encrypted** data. The result is a system where two parties can compute the intersection of their threat lists with **zero data leakage**.

6. I've built a full prototype with a real-time web dashboard that integrates live threat feeds like **URLhaus**. It proves we don't have to choose between privacy and security, we can have both.
