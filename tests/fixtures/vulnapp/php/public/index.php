<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use MongoDB\Client;
use MongoDB\Collection;
use Twig\Environment;
use Twig\Loader\FilesystemLoader;

const REPORT_DIR = '/srv/vulnapp/reports';
const RETURN_PAGES = ['cart' => '/cart', 'orders' => '/orders'];
const FORMULAS = ['net' => '100 * 0.8', 'gross' => '100 * 1.2'];
const STATUS_FEEDS = [
    'payments' => 'https://status.payments.vulnapp.internal/feed.json',
    'shipping' => 'https://status.shipping.vulnapp.internal/feed.json',
];

function search_items(mysqli $db): void
{
    $result = mysqli_query($db, "SELECT id, name FROM items WHERE name = '" . $_GET['name'] . "'");
    foreach (mysqli_fetch_all($result, MYSQLI_ASSOC) as $row) {
        echo htmlspecialchars($row['name'], ENT_QUOTES, 'UTF-8'), "\n";
    }
}

function filter_items(mysqli $db): void
{
    $stmt = mysqli_prepare($db, 'SELECT id, name FROM items WHERE name = ?');
    mysqli_stmt_bind_param($stmt, 's', $_GET['name']);
    mysqli_stmt_execute($stmt);
    foreach (mysqli_fetch_all(mysqli_stmt_get_result($stmt), MYSQLI_ASSOC) as $row) {
        echo htmlspecialchars($row['name'], ENT_QUOTES, 'UTF-8'), "\n";
    }
}

function ping_host(): void
{
    system('ping -c 1 ' . $_GET['host']);
}

function ping_host_v2(): void
{
    system('ping -c 1 ' . escapeshellarg($_GET['host']));
}

function show_page(): void
{
    include($_GET['page'] . '.php');
}

function show_page_v2(): void
{
    include(__DIR__ . '/pages/' . basename($_GET['page']) . '.php');
}

function load_preferences(): array
{
    return unserialize($_GET['prefs']);
}

function load_preferences_v2(): array
{
    return unserialize($_GET['prefs'], ['allowed_classes' => false]);
}

function search_page(): void
{
    echo '<h2>Results for ' . $_GET['q'] . '</h2>';
}

function search_page_compact(): void
{
    echo '<h2>Results for ' . htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8') . '</h2>';
}

function fetch_url(): string
{
    $ch = curl_init($_GET['url']);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    return (string) curl_exec($ch);
}

function fetch_feed(): string
{
    $ch = curl_init(STATUS_FEEDS[$_GET['feed']] ?? STATUS_FEEDS['payments']);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    return (string) curl_exec($ch);
}

function download_report(): void
{
    readfile(REPORT_DIR . '/' . $_GET['name']);
}

function download_summary(): void
{
    readfile(REPORT_DIR . '/' . basename($_GET['name']));
}

function continue_login(): void
{
    header('Location: ' . $_GET['next']);
}

function continue_logout(): void
{
    header('Location: ' . (RETURN_PAGES[$_GET['page']] ?? '/'));
}

function calculate(): float
{
    return eval('return ' . $_GET['expr'] . ';');
}

function calculate_v2(): float
{
    $formula = FORMULAS[$_GET['formula']] ?? '0';
    return eval('return ' . $formula . ';');
}

function render_note(Environment $twig): void
{
    $template = $twig->createTemplate($_POST['template']);
    echo $template->render(['name' => $_POST['name']]);
}

function render_note_v2(Environment $twig): void
{
    $template = $twig->load('note.twig');
    echo $template->render(['name' => $_POST['name']]);
}

function import_xml(): string
{
    $doc = simplexml_load_string(file_get_contents('php://input'), 'SimpleXMLElement', LIBXML_NOENT);
    return $doc->getName();
}

function import_xml_v2(): string
{
    $doc = simplexml_load_string(file_get_contents('php://input'), 'SimpleXMLElement', LIBXML_NONET);
    return $doc->getName();
}

function find_user(Collection $users): bool
{
    return $users->findOne(['username' => $_POST['username']]) !== null;
}

function find_user_v2(Collection $users): bool
{
    return $users->findOne(['username' => (string) $_POST['username']]) !== null;
}

function account_claims(): array
{
    $token = substr($_SERVER['HTTP_AUTHORIZATION'] ?? '', 7);
    return json_decode(base64_decode(strtr(explode('.', $token)[1] ?? '', '-_', '+/')), true);
}

function account_claims_v2(): array
{
    $token = substr($_SERVER['HTTP_AUTHORIZATION'] ?? '', 7);
    return (array) JWT::decode($token, new Key((string) getenv('VULNAPP_JWT_KEY'), 'HS256'));
}

function hash_password(string $password): string
{
    return md5($password);
}

function hash_password_v2(string $password): string
{
    return password_hash($password, PASSWORD_DEFAULT);
}

function seal_card(string $number): string
{
    return (string) openssl_encrypt($number, 'aes-256-ecb', (string) getenv('VULNAPP_CARD_KEY'));
}

function seal_card_v2(string $number): string
{
    $iv = random_bytes(12);
    $sealed = openssl_encrypt($number, 'aes-256-gcm', (string) getenv('VULNAPP_CARD_KEY'), 0, $iv, $tag);
    return base64_encode($iv . $tag) . ':' . $sealed;
}

function partner_cors(): void
{
    header('Access-Control-Allow-Origin: ' . $_SERVER['HTTP_ORIGIN']);
    header('Access-Control-Allow-Credentials: true');
}

function store_cors(): void
{
    header('Access-Control-Allow-Origin: https://shop.vulnapp.internal');
    header('Access-Control-Allow-Credentials: true');
}

$db = mysqli_connect((string) getenv('VULNAPP_DB_HOST'), (string) getenv('VULNAPP_DB_USER'), (string) getenv('VULNAPP_DB_PASS'), 'vulnapp');
$twig = new Environment(new FilesystemLoader(__DIR__ . '/../templates'));
$users = (new Client((string) getenv('VULNAPP_MONGO_URL')))->selectCollection('vulnapp', 'users');

switch ($_GET['action'] ?? '') {
    case 'search':
        search_items($db);
        break;
    case 'filter':
        filter_items($db);
        break;
    case 'ping':
        ping_host();
        break;
    case 'ping-v2':
        ping_host_v2();
        break;
    case 'page':
        show_page();
        break;
    case 'page-v2':
        show_page_v2();
        break;
    case 'prefs':
        echo json_encode(load_preferences());
        break;
    case 'prefs-v2':
        echo json_encode(load_preferences_v2());
        break;
    case 'results':
        search_page();
        break;
    case 'results-v2':
        search_page_compact();
        break;
    case 'fetch':
        echo json_encode(['body' => fetch_url()]);
        break;
    case 'feed':
        echo json_encode(['body' => fetch_feed()]);
        break;
    case 'report':
        download_report();
        break;
    case 'summary':
        download_summary();
        break;
    case 'login':
        continue_login();
        break;
    case 'logout':
        continue_logout();
        break;
    case 'calc':
        echo json_encode(['result' => calculate()]);
        break;
    case 'calc-v2':
        echo json_encode(['result' => calculate_v2()]);
        break;
    case 'note':
        render_note($twig);
        break;
    case 'note-v2':
        render_note_v2($twig);
        break;
    case 'import':
        echo json_encode(['root' => import_xml()]);
        break;
    case 'import-v2':
        echo json_encode(['root' => import_xml_v2()]);
        break;
    case 'user':
        echo json_encode(['found' => find_user($users)]);
        break;
    case 'user-v2':
        echo json_encode(['found' => find_user_v2($users)]);
        break;
    case 'account':
        echo json_encode(account_claims());
        break;
    case 'account-v2':
        echo json_encode(account_claims_v2());
        break;
    case 'register':
        $hash = hash_password($_POST['password']);
        mysqli_execute_query($db, 'INSERT INTO users (name, pw) VALUES (?, ?)', [$_POST['name'], $hash]);
        break;
    case 'password':
        $hash = hash_password_v2($_POST['password']);
        mysqli_execute_query($db, 'UPDATE users SET pw = ? WHERE id = ?', [$hash, 1]);
        break;
    case 'card':
        echo json_encode(['token' => seal_card((string) $_POST['number'])]);
        break;
    case 'card-v2':
        echo json_encode(['token' => seal_card_v2((string) $_POST['number'])]);
        break;
    case 'partner':
        partner_cors();
        break;
    default:
        store_cors();
        include __DIR__ . '/pages/home.php';
}
