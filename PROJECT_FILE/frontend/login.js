// login.js 

const LOGIN_API_URL = "http://localhost:5000/login";
const DB_INFO_URL = "http://localhost:5000/db/info";
const DB_INSTANCE_KEY = "securechat:db_instance_id";

document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("login-form");
    const banner = document.getElementById("message-banner");

    const usernameInput = document.getElementById("username");
    const passwordInput = document.getElementById("password");

    // --------------------------
    // Helper: Show message banner
    // --------------------------
    function showBanner(text, isError = false) {
        banner.textContent = text;
        banner.style.display = "block";
        banner.classList.remove("banner-error", "banner-success");
        banner.classList.add(isError ? "banner-error" : "banner-success");
    }

    // --------------------------
    // Login Form Handler
    // --------------------------
    form.addEventListener("submit", async (e) => {
        e.preventDefault();

        const username = usernameInput.value.trim();
        const password = passwordInput.value;

        if (!username || !password) {
            showBanner("Please enter both username and password.", true);
            return;
        }

        try {
            const resp = await fetch(LOGIN_API_URL, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username, password })
            });

            const data = await resp.json();

            if (!resp.ok) {
                showBanner(data.error || "Invalid credentials.", true);
                return;
            }

            // ----------------------
            // Save session data
            // ----------------------
            sessionStorage.setItem("token", data.token);
            sessionStorage.setItem("username", data.username);

            // Save ROLE so frontend knows if user is admin
            sessionStorage.setItem("role", data.role);   

            // Encrypted private key (must decrypt in chat.js)
            sessionStorage.setItem("encrypted_private_key", data.encrypted_private_key);

            // Store password temporarily so chat.js can decrypt RSA private key
            sessionStorage.setItem("user_password", password);

            // ----------------------
            // Sync DB instance id (helps detect DB resets cleanly)
            // ----------------------
            try {
                const dbResp = await fetch(DB_INFO_URL);
                if (dbResp.ok) {
                    const dbData = await dbResp.json();
                    if (dbData.db_instance_id) {
                        localStorage.setItem(DB_INSTANCE_KEY, dbData.db_instance_id);
                    }
                }
            } catch (e) {
                // ignore - not critical for login
            }

            // ----------------------
            // Redirect user
            // ----------------------
            showBanner("Login successful! Redirecting...");

            setTimeout(() => {
                if (data.role === "admin") {
                    window.location.href = "admin.html";   
                } else {
                    window.location.href = "chat.html";
                }
            }, 800);

        } catch (err) {
            console.error("Login error:", err);
            showBanner("Network error. Please try again.", true);
        }
    });
});
