// register.js - FINAL VERSION matching new backend

const REGISTER_API_URL = "http://localhost:5000/register";

document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("register-form");

    const usernameInput = document.getElementById("username");
    const passwordInput = document.getElementById("password");
    const confirmInput = document.getElementById("confirm-password");

    const banner = document.getElementById("message-banner");

    // -------------------------
    // Helper: Show banner
    // -------------------------
    function showBanner(text, isError = false) {
        banner.textContent = text;
        banner.style.display = "block";
        banner.classList.remove("banner-error", "banner-success");
        banner.classList.add(isError ? "banner-error" : "banner-success");
    }

    // -------------------------
    // Registration Handler
    // -------------------------
    form.addEventListener("submit", async (e) => {
        e.preventDefault();

        const username = usernameInput.value.trim();
        const password = passwordInput.value;
        const confirm = confirmInput.value;

        // Basic validation
        if (!username || !password || !confirm) {
            showBanner("All fields are required.", true);
            return;
        }

        if (password !== confirm) {
            showBanner("Passwords do not match.", true);
            return;
        }

        // Password strength must match backend regex
        const strongPasswordPattern =
            /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$/;

        if (!strongPasswordPattern.test(password)) {
            showBanner(
                "Password must be at least 8 characters and include uppercase, lowercase, number, and special character.",
                true
            );
            return;
        }

        // -----------------------------
        // Send registration request
        // -----------------------------
        try {
            const resp = await fetch(REGISTER_API_URL, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username, password })
            });

            const data = await resp.json();

            if (!resp.ok) {
                showBanner(data.error || "Registration failed.", true);
                return;
            }

            // Success
            showBanner("Registration successful! Redirecting to login...");

            setTimeout(() => {
                window.location.href = "login.html";
            }, 1200);

        } catch (err) {
            console.error("Register error:", err);
            showBanner("Network error. Please try again.", true);
        }
    });
});
