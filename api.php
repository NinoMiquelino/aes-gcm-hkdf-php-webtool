<?php

// Configuração de cabeçalhos CORS (para testes locais, ajuste em produção)
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *'); // Mudar para o domínio do frontend em produção
header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

// --- Funções de Criptografia/Descriptografia ---

/**
 * Criptografa os dados utilizando AES-256-GCM.
 *
 * @param string $data Os dados a serem criptografados.
 * @param string $key A chave hexadecimal de 64 caracteres.
 * @param string $url A URL usada como Dados Autenticados Adicionais (AAD).
 * @return string Dados criptografados (IV + Tag + Texto Cifrado).
 * @throws InvalidArgumentException Se os parâmetros forem inválidos.
 * @throws RuntimeException Se a criptografia falhar.
 */
function encryptData($data, $key, $url) {
	$aad = $url;	
	
    // Nome do algoritmo
    $cipher = 'aes-256-gcm';
	
    // Validar dados
    if (!is_string($data)) {
        throw new InvalidArgumentException("Os dados fornecidos para criptografia não são uma string.");
    }

    // Validar chave
    if (!is_string($key) || strlen($key) !== 64 || !ctype_xdigit($key)) {
        throw new InvalidArgumentException("A chave de criptografia não está definida adequadamente.");
    }

    // Normalizar os dados (opcional)
    if (class_exists('Normalizer')) {
        $data = normalizer_normalize($data, Normalizer::FORM_C);
    }

    // Derivar chave      
    $key = hash_hkdf('sha256', hex2bin($key), 32, '', 'application-specific-salt'); // Adicionar hex2bin

    // Gerar IV
    try {     
        $ivLength = openssl_cipher_iv_length($cipher);
        $iv = random_bytes($ivLength);
    } catch (Exception $e) {
        throw new RuntimeException("Falha ao gerar o IV: " . $e->getMessage());
    }

    // Inicializar tag de autenticação
    $tag = null;

    // Criptografar
    $encrypted = openssl_encrypt($data, $cipher, $key, OPENSSL_RAW_DATA, $iv, $tag, $aad);

    // Validar criptografia
    if ($encrypted === false || $tag === null) {
        throw new RuntimeException("Falha na criptografia dos dados.");
    }

    // Retornar dados criptografados
    
    unset($key);
    
    return base64_encode($iv . $tag . $encrypted); // Usar Base64 para garantir que seja string segura para JSON
}

/**
 * Descriptografa os dados utilizando AES-256-GCM.
 *
 * @param string $data Dados criptografados (IV + Tag + Texto Cifrado em Base64).
 * @param string $key A chave hexadecimal de 64 caracteres.
 * @param string $url A URL usada como Dados Autenticados Adicionais (AAD).
 * @return string Dados descriptografados.
 * @throws InvalidArgumentException Se os parâmetros forem inválidos.
 * @throws RuntimeException Se o formato dos dados ou a descriptografia falharem.
 */
function decryptData($data, $key, $url) {	
	$aad = $url;	
	
	// Nome do algoritmo
    $cipher = 'aes-256-gcm';
	
    // Validar dados
    if (!is_string($data)) {
        throw new InvalidArgumentException("Os dados fornecidos para descriptografia não são uma string.");
    }
    
    // Decodificar Base64
    $data_bin = base64_decode($data, true);
    if ($data_bin === false) {
        throw new RuntimeException("Dados criptografados não estão em formato Base64 válido.");
    }
    $data = $data_bin;

    // Validar chave
    if (!is_string($key) || strlen($key) !== 64 || !ctype_xdigit($key)) {
        throw new InvalidArgumentException("A chave de criptografia não está definida adequadamente.");
    }

    // Derivar chave    
    $key = hash_hkdf('sha256', hex2bin($key), 32, '', 'application-specific-salt'); // Adicionar hex2bin
    
    // Calcular tamanho do IV e da tag com base no algoritmo
    $ivLength = openssl_cipher_iv_length($cipher); // Geralmente 12 para GCM
    $tagLength = 16; // AES-GCM usa 128-bit tag (16 bytes)

    // Recuperar IV, tag e texto cifrado
    $iv = substr($data, 0, $ivLength);
    $tag = substr($data, $ivLength, $tagLength);
    $encrypted = substr($data, $ivLength + $tagLength);       
    
    if (empty($encrypted)) {
        return '';
    }
    
    // Validar tamanhos
    if (strlen($iv) !== $ivLength || strlen($tag) !== $tagLength || empty($encrypted)) {
        throw new RuntimeException("Formato de dados criptografados inválido.");
    }   
    

    // Descriptografar    
    $decrypted = openssl_decrypt($encrypted, $cipher, $key, OPENSSL_RAW_DATA, $iv, $tag, $aad);

    // Validar descriptografia
    if ($decrypted === false) {
        throw new RuntimeException("Falha na descriptografia dos dados.");
    }
    
    // Normalizar os dados (opcional, se normalizado na criptografia)
    if (class_exists('Normalizer')) {
        $decrypted = normalizer_normalize($decrypted, Normalizer::FORM_C);
    }

    unset($key);
    unset($iv);
    unset($tag);

    return $decrypted;
}


// --- Lógica da API ---

$method = $_SERVER['REQUEST_METHOD'] ?? '';

if ($method === 'POST') {
    // Pegar os dados JSON do corpo da requisição
    $input = file_get_contents('php://input');
    $data = json_decode($input, true);

    $action = $data['action'] ?? '';
    $key = $data['key'] ?? '';
    $url = $data['url'] ?? '';
    $payload = $data['payload'] ?? '';

    $result = ['success' => false, 'data' => '', 'error' => ''];

    try {
        if (empty($key) || empty($url)) {
            throw new InvalidArgumentException("Chave ou URL não podem estar vazias.");
        }

        if ($action === 'encrypt') {
            if (empty($payload)) {
                 throw new InvalidArgumentException("Dados para criptografar não podem estar vazios.");
            }
            $encryptedData = encryptData($payload, $key, $url);
            $result['success'] = true;
            $result['data'] = $encryptedData;

        } elseif ($action === 'decrypt') {
            if (empty($payload)) {
                 throw new InvalidArgumentException("String para descriptografar não pode estar vazia.");
            }
            $decryptedData = decryptData($payload, $key, $url);
            $result['success'] = true;
            $result['data'] = $decryptedData;

        } else {
            $result['error'] = 'Ação inválida.';
        }
    } catch (InvalidArgumentException $e) {
        // Erro de validação de input
        http_response_code(400);
        $result['error'] = 'Erro de Argumento: ' . $e->getMessage();
    } catch (RuntimeException $e) {
        // Erro de criptografia/descriptografia
        http_response_code(500);
        $result['error'] = 'Erro de Processamento: ' . $e->getMessage();
    } catch (Exception $e) {
        // Outros erros
        http_response_code(500);
        $result['error'] = 'Erro inesperado: ' . $e->getMessage();
    }

    echo json_encode($result);
    
} elseif ($method === 'OPTIONS') {
    // Resposta para preflight request do CORS
    http_response_code(200);
    exit();
} else {
    // Método não permitido
    http_response_code(405);
    echo json_encode(['success' => false, 'error' => 'Método não permitido.']);
}

?>
