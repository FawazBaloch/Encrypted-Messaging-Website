// index.js - Landing Page JavaScript
// This file handles the landing page logic

/**
 * This page is very simple - just static HTML with navigation links
 * No complex JavaScript needed here
 * 
 * The page provides:
 * - Welcome message
 * - Feature list
 * - Links to register/login pages
 * 
 * If you wanted to add features, you could:
 * - Check if user is already logged in (redirect to chat)
 * - Add animations
 * - Add a demo video
 */

// Check if user is already logged in when page loads
document.addEventListener('DOMContentLoaded', function() {
    // Get JWT token from sessionStorage
    const token = sessionStorage.getItem('token');
    
    // If user already has valid token, redirect to appropriate page
    if (token) {
        const role = sessionStorage.getItem('role');
        
        // Redirect based on role
        if (role === 'admin') {
            window.location.href = 'admin.html';
        } else {
            window.location.href = 'chat.html';
        }
    }
    
    // If no token, stay on landing page (user needs to register/login)
});