// =============================================================================
// SWEET ALERT ERROR HANDLING SYSTEM
// =============================================================================
// This file provides a comprehensive error handling system using Sweet Alert 2
// to display user-friendly error messages instead of raw JSON responses.
//
// Features:
// - Consistent error display across the application
// - Different alert types (error, success, warning, info)
// - Automatic flash message handling
// - AJAX error handling
// - Form validation error display
// =============================================================================

/**
 * Display an error alert with red styling
 * @param {string} title - Alert title (default: 'Error')
 * @param {string} message - Error message to display
 * @param {function} callback - Optional callback function after user confirms
 */
function showErrorAlert(title, message, callback = null) {
    Swal.fire({
        icon: 'error',
        title: title || 'Error',
        text: message || 'An unexpected error occurred',
        confirmButtonText: 'OK',
        confirmButtonColor: '#dc2626', // Red color for errors
        allowOutsideClick: false,
        allowEscapeKey: true
    }).then((result) => {
        if (callback && typeof callback === 'function') {
            callback(result);
        }
    });
}

/**
 * Display a success alert with green styling
 * @param {string} title - Alert title (default: 'Success')
 * @param {string} message - Success message to display
 * @param {function} callback - Optional callback function after user confirms
 */
function showSuccessAlert(title, message, callback = null) {
    Swal.fire({
        icon: 'success',
        title: title || 'Success',
        text: message || 'Operation completed successfully',
        confirmButtonText: 'OK',
        confirmButtonColor: '#059669', // Green color for success
        allowOutsideClick: false,
        allowEscapeKey: true
    }).then((result) => {
        if (callback && typeof callback === 'function') {
            callback(result);
        }
    });
}

/**
 * Display a warning alert with orange styling
 * @param {string} title - Alert title (default: 'Warning')
 * @param {string} message - Warning message to display
 * @param {function} callback - Optional callback function after user confirms
 */
function showWarningAlert(title, message, callback = null) {
    Swal.fire({
        icon: 'warning',
        title: title || 'Warning',
        text: message || 'Please check your input',
        confirmButtonText: 'OK',
        confirmButtonColor: '#d97706', // Orange color for warnings
        allowOutsideClick: false,
        allowEscapeKey: true
    }).then((result) => {
        if (callback && typeof callback === 'function') {
            callback(result);
        }
    });
}

/**
 * Display an info alert with blue styling
 * @param {string} title - Alert title (default: 'Information')
 * @param {string} message - Information message to display
 * @param {function} callback - Optional callback function after user confirms
 */
function showInfoAlert(title, message, callback = null) {
    Swal.fire({
        icon: 'info',
        title: title || 'Information',
        text: message || 'Please note',
        confirmButtonText: 'OK',
        confirmButtonColor: '#2563eb', // Blue color for info
        allowOutsideClick: false,
        allowEscapeKey: true
    }).then((result) => {
        if (callback && typeof callback === 'function') {
            callback(result);
        }
    });
}

// =============================================================================
// AJAX ERROR HANDLING
// =============================================================================

/**
 * Handle AJAX/fetch errors globally with appropriate error messages
 * @param {XMLHttpRequest} xhr - The XMLHttpRequest object
 * @param {string} status - The status text
 * @param {string} error - The error message
 */
function handleAjaxError(xhr, status, error) {
    let errorMessage = 'An unexpected error occurred';
    let errorTitle = 'Error';
    
    // Extract error message from response
    if (xhr.responseJSON && xhr.responseJSON.error) {
        errorMessage = xhr.responseJSON.error;
    } else if (xhr.responseText) {
        try {
            const response = JSON.parse(xhr.responseText);
            if (response.error) {
                errorMessage = response.error;
            }
        } catch (e) {
            // If response is not JSON, use status text
            errorMessage = xhr.statusText || 'Network error';
        }
    }
    
    // Customize error title based on HTTP status code
    switch (xhr.status) {
        case 400:
            errorTitle = 'Invalid Request';
            break;
        case 401:
            errorTitle = 'Authentication Required';
            break;
        case 403:
            errorTitle = 'Access Denied';
            break;
        case 404:
            errorTitle = 'Not Found';
            break;
        case 409:
            errorTitle = 'Conflict';
            break;
        case 500:
            errorTitle = 'Server Error';
            break;
        default:
            errorTitle = 'Error';
    }
    
    showErrorAlert(errorTitle, errorMessage);
}

// =============================================================================
// ENHANCED FETCH FUNCTION
// =============================================================================

/**
 * Enhanced fetch function with automatic error handling
 * @param {string} url - The URL to fetch
 * @param {object} options - Fetch options (headers, method, body, etc.)
 * @returns {Promise} - Promise that resolves to JSON response or shows error alert
 */
async function fetchWithErrorHandling(url, options = {}) {
    try {
        const response = await fetch(url, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            }
        });
        
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({ error: 'Network error' }));
            throw new Error(errorData.error || `HTTP ${response.status}: ${response.statusText}`);
        }
        
        return await response.json();
    } catch (error) {
        showErrorAlert('Request Failed', error.message);
        throw error;
    }
}

// =============================================================================
// FORM ERROR HANDLING
// =============================================================================

/**
 * Handle form submission errors by displaying both inline and popup messages
 * @param {HTMLElement} form - The form element that has an error
 * @param {string} error - The error message to display
 */
function handleFormError(form, error) {
    // Remove any existing error messages to prevent duplicates
    form.querySelectorAll('.error-message').forEach(el => el.remove());
    
    // Create and add inline error message
    const errorDiv = document.createElement('div');
    errorDiv.className = 'error-message text-red-600 text-sm mt-2';
    errorDiv.textContent = error;
    
    // Insert error message after the form
    form.parentNode.insertBefore(errorDiv, form.nextSibling);
    
    // Show Sweet Alert popup for better visibility
    showErrorAlert('Form Error', error);
}

// =============================================================================
// INITIALIZATION AND AUTOMATIC MESSAGE HANDLING
// =============================================================================

/**
 * Initialize error handling system when the page loads
 * This function automatically processes and displays any server-side messages
 */
document.addEventListener('DOMContentLoaded', function() {
    // Handle server-side error messages (from templates)
    const errorMessages = document.querySelectorAll('.server-error');
    errorMessages.forEach(element => {
        const title = element.dataset.title || 'Error';
        const message = element.textContent || element.dataset.message;
        showErrorAlert(title, message);
        element.remove(); // Remove from DOM after showing alert
    });
    
    // Handle server-side success messages (from templates)
    const successMessages = document.querySelectorAll('.server-success');
    successMessages.forEach(element => {
        const title = element.dataset.title || 'Success';
        const message = element.textContent || element.dataset.message;
        showSuccessAlert(title, message);
        element.remove(); // Remove from DOM after showing alert
    });
    
    // Handle Flask flash messages (from server redirects)
    const flashMessages = document.querySelectorAll('.flash-message');
    flashMessages.forEach(function(element) {
        const category = element.dataset.category;
        const message = element.dataset.message;
        
        // Display appropriate alert based on message category
        if (category === 'error') {
            showErrorAlert('Error', message);
        } else if (category === 'success') {
            showSuccessAlert('Success', message);
        } else if (category === 'warning') {
            showWarningAlert('Warning', message);
        } else {
            showInfoAlert('Information', message);
        }
        
        element.remove(); // Clean up DOM after displaying
    });
});
