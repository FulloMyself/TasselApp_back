<?php
// send-email.php
// Simple PHP endpoint to accept JSON payload and send email via mail().
// Expected JSON: { to, subject, text, html, apiKey }

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

$raw = file_get_contents('php://input');
if (!$raw) {
    echo json_encode(['error' => 'Empty request']);
    http_response_code(400);
    exit();
}

$data = json_decode($raw, true);
if (json_last_error() !== JSON_ERROR_NONE) {
    echo json_encode(['error' => 'Invalid JSON']);
    http_response_code(400);
    exit();
}

$required = ['to', 'subject'];
foreach ($required as $r) {
    if (empty($data[$r])) {
        echo json_encode(['error' => "Missing field: $r"]);
        http_response_code(400);
        exit();
    }
}

// Optional API key check
$expectedKey = getenv('PHP_MAIL_KEY');
if ($expectedKey && (!isset($data['apiKey']) || $data['apiKey'] !== $expectedKey)) {
    echo json_encode(['error' => 'Unauthorized']);
    http_response_code(403);
    exit();
}

$to = filter_var($data['to'], FILTER_SANITIZE_EMAIL);
$subject = substr(strip_tags($data['subject']), 0, 200);
$text = isset($data['text']) ? $data['text'] : '';
$html = isset($data['html']) ? $data['html'] : $text;

// Build headers for HTML email
$headers = "MIME-Version: 1.0" . "\r\n";
$headers .= "Content-type:text/html;charset=UTF-8" . "\r\n";
$from = getenv('FROM_EMAIL') ?: null;
if ($from) {
    $headers .= "From: " . $from . "\r\n";
}

$success = false;
try {
    // Use mail(); on many hosts this will be forwarded via sendmail/postfix
    $mailBody = $html ?: $text;
    if (@mail($to, $subject, $mailBody, $headers)) {
        $success = true;
        echo json_encode(['success' => true, 'message' => 'Email queued for delivery']);
    } else {
        // mail() failed — return error so caller can fallback
        echo json_encode(['error' => 'mail() failed']);
        http_response_code(500);
    }
} catch (Exception $e) {
    error_log('Mail error: ' . $e->getMessage());
    echo json_encode(['error' => 'Exception while sending email']);
    http_response_code(500);
}

?>
