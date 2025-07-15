import React, { useState, useEffect, useMemo } from 'react';
import CryptoJS from 'crypto-js';

// --- SVG Icons ---
const LockIcon = ({ className = "w-5 h-5" }) => (
  <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
);
const UnlockIcon = ({ className = "w-5 h-5" }) => (
  <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 9.9-1"></path></svg>
);
const HashIcon = ({ className = "w-5 h-5" }) => (
  <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}><line x1="4" y1="9" x2="20" y2="9"></line><line x1="4" y1="15" x2="20" y2="15"></line><line x1="10" y1="3" x2="8" y2="21"></line><line x1="16" y1="3" x2="14" y2="21"></line></svg>
);
const CopyIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="w-4 h-4"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
);
const CheckIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" className="w-4 h-4 text-green-400"><polyline points="20 6 9 17 4 12"></polyline></svg>
);
const ArrowRightIcon = () => (
    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="w-4 h-4 ml-1"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>
);


// --- Algorithm Definitions ---
const ALGORITHMS = {
  Symmetric: {
    aes: {
      name: 'AES-GCM',
      fullName: 'AES-GCM (Web Crypto)',
      description: 'The modern industry standard for symmetric encryption. Uses the browser\'s native Web Crypto API for high performance and security (PBKDF2 key derivation, Salt, and IV).',
      requiresKey: true, canDecrypt: true, link: 'https://en.wikipedia.org/wiki/Advanced_Encryption_Standard', icon: LockIcon,
    },
    '3des': {
      name: 'Triple DES',
      fullName: 'Triple DES (3DES)',
      description: 'An older symmetric-key block cipher created to extend the life of DES. It applies the DES cipher algorithm three times to each data block. Now considered slow and deprecated.',
      requiresKey: true, canDecrypt: true, link: 'https://en.wikipedia.org/wiki/Triple_DES', icon: LockIcon,
    },
    rabbit: {
      name: 'Rabbit',
      fullName: 'Rabbit Stream Cipher',
      description: 'A high-performance stream cipher, and one of the finalists in the eSTREAM project. It is fast but less common than block ciphers like AES or modern stream ciphers like ChaCha20.',
      requiresKey: true, canDecrypt: true, link: 'https://en.wikipedia.org/wiki/Rabbit_(cipher)', icon: LockIcon,
    },
    caesar: {
      name: 'Caesar Cipher',
      fullName: 'Caesar Cipher',
      description: 'A simple substitution cipher for educational purposes. Each letter is shifted by a set number of places (the key). Not secure for real-world use.',
      requiresKey: true, canDecrypt: true, link: 'https://en.wikipedia.org/wiki/Caesar_cipher', icon: UnlockIcon, type: 'number', placeholder: 'e.g., 3'
    },
  },
  Hashing: {
    sha256: {
      name: 'SHA-256',
      fullName: 'SHA-256 Hash',
      description: 'The industry standard cryptographic hash function from the SHA-2 family. Produces a 256-bit (32-byte) hash. Widely used in blockchain and digital signatures.',
      requiresKey: false, canDecrypt: false, link: 'https://en.wikipedia.org/wiki/SHA-2', icon: HashIcon,
    },
    sha512: {
        name: 'SHA-512',
        fullName: 'SHA-512 Hash',
        description: 'A more robust version of SHA-2, producing a 512-bit (64-byte) hash. It is often faster than SHA-256 on 64-bit processors.',
        requiresKey: false, canDecrypt: false, link: 'https://en.wikipedia.org/wiki/SHA-2', icon: HashIcon,
    },
    sha1: {
      name: 'SHA-1',
      fullName: 'SHA-1 Hash (Insecure)',
      description: 'A deprecated hash function. It is no longer considered secure against well-funded attackers due to known collision vulnerabilities. Included for educational purposes.',
      requiresKey: false, canDecrypt: false, link: 'https://en.wikipedia.org/wiki/SHA-1', icon: WarningIcon,
    },
    md5: {
      name: 'MD5',
      fullName: 'MD5 Hash (Broken)',
      description: 'A broken hash function, highly vulnerable to collisions. It should never be used for security purposes. Useful for demonstrating why cryptographic hash functions must be collision-resistant.',
      requiresKey: false, canDecrypt: false, link: 'https://en.wikipedia.org/wiki/MD5', icon: WarningIcon,
    },
  },
};

// --- Web Crypto API Helpers ---
const enc = new TextEncoder();
const dec = new TextDecoder();
const getCryptoKey = async (password, salt) => {
  const keyMaterial = await window.crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveKey']);
  return window.crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, keyMaterial, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
};
const encryptAES = async (text, password) => {
  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const key = await getCryptoKey(password, salt);
  const encrypted = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(text));
  const combined = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
  combined.set(salt, 0); combined.set(iv, salt.length); combined.set(new Uint8Array(encrypted), salt.length + iv.length);
  return btoa(String.fromCharCode.apply(null, combined));
};
const decryptAES = async (base64Ciphertext, password) => {
  const combined = new Uint8Array(atob(base64Ciphertext).split('').map(c => c.charCodeAt(0)));
  const salt = combined.slice(0, 16); const iv = combined.slice(16, 28); const ciphertext = combined.slice(28);
  const key = await getCryptoKey(password, salt);
  const decrypted = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return dec.decode(decrypted);
};
const caesarCipher = (str, shift) => str.replace(/[a-zA-Z]/g, (char) => {
  const base = char.charCodeAt(0) < 97 ? 65 : 97;
  return String.fromCharCode(((char.charCodeAt(0) - base + shift) % 26 + 26) % 26 + base);
});
const cryptoJsCipher = (algo, text, key, mode) => {
    const keyUtf8 = CryptoJS.enc.Utf8.parse(key);
    if (mode === 'encrypt') {
        const encrypted = algo.encrypt(text, keyUtf8, { iv: keyUtf8 });
        return encrypted.toString();
    } else {
        const decrypted = algo.decrypt(text, keyUtf8, { iv: keyUtf8 });
        return decrypted.toString(CryptoJS.enc.Utf8);
    }
};

// --- UI Components ---
const AlgorithmDiagram = ({ algorithm }) => {
    // Simplified for brevity, you can create more detailed diagrams
    const diagrams = {
        aes: <div className="p-4 bg-white/5 rounded-lg border border-white/10"><h3 className="text-lg font-bold text-center text-white">AES-GCM Encryption Flow</h3><p className="text-center text-sm text-gray-400 mt-2">Plaintext + Secret Key → PBKDF2 → AES-GCM Encrypt (+ Salt/IV) → Ciphertext</p></div>,
        '3des': <div className="p-4 bg-white/5 rounded-lg border border-white/10"><h3 className="text-lg font-bold text-center text-white">Triple DES Flow</h3><p className="text-center text-sm text-gray-400 mt-2">Plaintext → Encrypt (Key1) → Decrypt (Key2) → Encrypt (Key3) → Ciphertext</p></div>,
        rabbit: <div className="p-4 bg-white/5 rounded-lg border border-white/10"><h3 className="text-lg font-bold text-center text-white">Rabbit Stream Cipher</h3><p className="text-center text-sm text-gray-400 mt-2">Plaintext ⊕ Keystream (from Key+IV) → Ciphertext</p></div>,
        caesar: <div className="p-4 bg-white/5 rounded-lg border border-white/10"><h3 className="text-lg font-bold text-center text-white">Caesar Cipher Flow</h3><p className="text-center text-sm text-gray-400 mt-2">"ABC" + Key(3) → Shift Letters → "DEF"</p></div>,
        sha256: <div className="p-4 bg-white/5 rounded-lg border border-white/10"><h3 className="text-lg font-bold text-center text-white">SHA-256 Hashing Flow</h3><p className="text-center text-sm text-gray-400 mt-2">Any Input → SHA-256 Function → Fixed-Length 256-bit Hash</p></div>,
        sha512: <div className="p-4 bg-white/5 rounded-lg border border-white/10"><h3 className="text-lg font-bold text-center text-white">SHA-512 Hashing Flow</h3><p className="text-center text-sm text-gray-400 mt-2">Any Input → SHA-512 Function → Fixed-Length 512-bit Hash</p></div>,
        sha1: <div className="p-4 bg-white/5 rounded-lg border border-white/10"><h3 className="text-lg font-bold text-center text-rose-400">SHA-1 (Insecure)</h3><p className="text-center text-sm text-gray-400 mt-2">Any Input → SHA-1 Function → Fixed-Length 160-bit Hash (Vulnerable to Collisions)</p></div>,
        md5: <div className="p-4 bg-white/5 rounded-lg border border-white/10"><h3 className="text-lg font-bold text-center text-red-500">MD5 (Broken)</h3><p className="text-center text-sm text-gray-400 mt-2">Any Input → MD5 Function → Fixed-Length 128-bit Hash (Collisions are easy to find)</p></div>,
    };
    return diagrams[algorithm] || null;
};
const AlgorithmInfo = ({ algorithm }) => {
    const allAlgos = { ...ALGORITHMS.Symmetric, ...ALGORITHMS.Hashing };
    const info = allAlgos[algorithm];
    if (!info) return null;
    return (
        <div className="p-4 bg-white/5 rounded-lg border border-white/10 flex flex-col justify-between h-full">
            <div>
                <h3 className="font-semibold text-lg text-white mb-2">{info.fullName}</h3>
                <p className="text-sm text-gray-400">{info.description}</p>
            </div>
            <a href={info.link} target="_blank" rel="noopener noreferrer" className="inline-flex items-center justify-center text-sm font-semibold text-indigo-400 hover:text-indigo-300 mt-4 transition-colors">
                Read More on Wikipedia <ArrowRightIcon />
            </a>
        </div>
    );
};

const Sidebar = ({ activeAlgorithm, onAlgorithmChange }) => (
    <aside className="w-64 bg-black/30 backdrop-blur-xl border-r border-white/10 p-4 flex-col hidden md:flex">
        <h1 className="text-2xl font-bold text-white mb-8 px-2 bg-clip-text text-transparent bg-gradient-to-r from-indigo-400 to-cyan-400">Crypto Playground</h1>
        {Object.entries(ALGORITHMS).map(([groupName, algos]) => (
            <div key={groupName} className="mb-6">
                <h2 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3 px-3">{groupName}</h2>
                {Object.entries(algos).map(([id, algo]) => {
                    const Icon = algo.icon;
                    const isActive = activeAlgorithm === id;
                    return (
                        <button
                            key={id}
                            onClick={() => onAlgorithmChange(id)}
                            className={`flex items-center gap-3 w-full text-left px-3 py-2.5 rounded-lg transition-all duration-200 text-base ${isActive ? 'bg-indigo-600 text-white shadow-lg' : 'text-gray-300 hover:bg-white/10'}`}
                        >
                            <Icon className={`w-5 h-5 ${id === 'sha1' || id === 'md5' ? (isActive ? 'text-white' : 'text-amber-400') : ''}`} />
                            <span>{algo.name}</span>
                        </button>
                    )
                })}
            </div>
        ))}
    </aside>
);

const Content = ({ algorithm, mode, setMode, inputText, setInputText, secretKey, setSecretKey, outputText, error, isProcessing, handleCopy, copied }) => {
    const allAlgos = { ...ALGORITHMS.Symmetric, ...ALGORITHMS.Hashing };
    const currentAlgorithm = allAlgos[algorithm];

    return (
        <main className="flex-1 p-6 md:p-8 overflow-y-auto">
            <div className="max-w-4xl mx-auto">
                <div className="mb-8">
                    <h1 className="text-4xl md:text-5xl font-bold text-white">{currentAlgorithm.name}</h1>
                    <p className="text-lg text-gray-400 mt-2">{currentAlgorithm.fullName}</p>
                </div>

                <div className="space-y-6">
                    {/* Input & Output */}
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                        <div className="relative">
                            <label htmlFor="inputText" className="block text-sm font-medium text-gray-300 mb-2">{mode === 'encrypt' ? 'Plaintext Input' : 'Ciphertext Input'}</label>
                            <textarea id="inputText" rows="6" value={inputText} onChange={(e) => setInputText(e.target.value)} placeholder="Type or paste your message here..." className="w-full bg-black/30 border border-white/20 text-white rounded-lg p-3 focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition-all duration-300 resize-none placeholder-gray-500"></textarea>
                        </div>
                        <div className="relative">
                             <div className="flex justify-between items-center mb-2">
                                <label htmlFor="outputText" className="block text-sm font-medium text-gray-300">
                                    {isProcessing ? 'Processing...' : (error ? 'Error' : 'Output')}
                                </label>
                                <button onClick={handleCopy} className="flex items-center gap-2 text-xs bg-white/10 hover:bg-white/20 text-gray-300 font-semibold py-1 px-3 rounded-full transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed" disabled={!outputText || !!error || isProcessing}>
                                    {copied ? <CheckIcon /> : <CopyIcon />} {copied ? 'Copied!' : 'Copy'}
                                </button>
                            </div>
                            <textarea id="outputText" rows="6" readOnly value={isProcessing ? '' : (error || outputText)} placeholder={isProcessing ? '...' : "Result will appear here..." } className={`w-full bg-black/30 border rounded-lg p-3 transition-all duration-300 resize-none ${error ? 'text-red-400 border-red-500/50' : 'text-emerald-300 border-white/20'} ${isProcessing ? 'animate-pulse' : ''}`}></textarea>
                        </div>
                    </div>

                    {/* Controls */}
                    <div className="bg-black/20 border border-white/10 rounded-lg p-4">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 items-end">
                             {currentAlgorithm.requiresKey && (
                                <div>
                                    <label htmlFor="secretKey" className="block text-sm font-medium text-gray-300 mb-2">Secret Key</label>
                                    <input id="secretKey" type={currentAlgorithm.type || "text"} value={secretKey} onChange={(e) => setSecretKey(e.target.value)} placeholder={currentAlgorithm.placeholder || "Enter secret key"} className="w-full bg-black/30 border border-white/20 text-white rounded-lg p-3 focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition-all duration-300" />
                                </div>
                            )}
                            {currentAlgorithm.canDecrypt && (
                                <div>
                                    <label className="block text-sm font-medium text-gray-300 mb-2">Mode</label>
                                    <div className="flex items-center bg-black/30 rounded-lg p-1 h-[46px]">
                                        <button onClick={() => setMode('encrypt')} className={`w-1/2 h-full flex items-center justify-center gap-2 text-sm rounded-md transition-all duration-300 ${mode === 'encrypt' ? 'bg-indigo-600 text-white shadow' : 'text-gray-300 hover:bg-white/10'}`}><LockIcon /> Encrypt</button>
                                        <button onClick={() => setMode('decrypt')} className={`w-1/2 h-full flex items-center justify-center gap-2 text-sm rounded-md transition-all duration-300 ${mode === 'decrypt' ? 'bg-teal-600 text-white shadow' : 'text-gray-300 hover:bg-white/10'}`}><UnlockIcon /> Decrypt</button>
                                    </div>
                                </div>
                            )}
                            {!currentAlgorithm.requiresKey && (
                                <div className="text-center text-gray-400 text-sm md:col-span-2">This is a one-way hash function. No key or decryption is needed.</div>
                            )}
                        </div>
                    </div>

                    {/* Info and Diagram */}
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 pt-4">
                        <AlgorithmInfo algorithm={algorithm} />
                        <AlgorithmDiagram algorithm={algorithm} />
                    </div>
                </div>
            </div>
        </main>
    );
};

// --- Main App Component ---
export default function App() {
  const [algorithm, setAlgorithm] = useState('aes');
  const [mode, setMode] = useState('encrypt');
  const [inputText, setInputText] = useState('Hello, secure world!');
  const [secretKey, setSecretKey] = useState('MySecretKey');
  const [outputText, setOutputText] = useState('');
  const [error, setError] = useState('');
  const [copied, setCopied] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);

  const allAlgos = useMemo(() => ({ ...ALGORITHMS.Symmetric, ...ALGORITHMS.Hashing }), []);
  const currentAlgorithm = useMemo(() => allAlgos[algorithm], [algorithm, allAlgos]);

  useEffect(() => {
    const processCrypto = async () => {
      if (!inputText) { setOutputText(''); setError(''); return; }
      if (!currentAlgorithm.canDecrypt && mode === 'decrypt') { setMode('encrypt'); }
      
      setIsProcessing(true);
      setError('');
      setOutputText('');

      try {
        let result = '';
        if (currentAlgorithm.requiresKey && !secretKey) throw new Error('A secret key is required.');

        switch (algorithm) {
          case 'aes':
            result = mode === 'encrypt' ? await encryptAES(inputText, secretKey) : await decryptAES(inputText, secretKey);
            break;
          case 'caesar':
            const shift = parseInt(secretKey, 10);
            if (isNaN(shift)) throw new Error('A numeric key is required for Caesar Cipher.');
            result = caesarCipher(inputText, mode === 'encrypt' ? shift : -shift);
            break;
          case '3des':
            result = cryptoJsCipher(CryptoJS.TripleDES, inputText, secretKey, mode);
            if (!result) throw new Error("Decryption failed. Check key or ciphertext.");
            break;
          case 'rabbit':
            result = cryptoJsCipher(CryptoJS.Rabbit, inputText, secretKey, mode);
            if (!result) throw new Error("Decryption failed. Check key or ciphertext.");
            break;
          case 'sha256': result = CryptoJS.SHA256(inputText).toString(CryptoJS.enc.Hex); break;
          case 'sha512': result = CryptoJS.SHA512(inputText).toString(CryptoJS.enc.Hex); break;
          case 'sha1': result = CryptoJS.SHA1(inputText).toString(CryptoJS.enc.Hex); break;
          case 'md5': result = CryptoJS.MD5(inputText).toString(CryptoJS.enc.Hex); break;
          default: throw new Error("Algorithm not implemented.");
        }
        setOutputText(result);
      } catch (e) {
        setError(e.message || 'An error occurred. Check your input or key.');
        setOutputText('');
      } finally {
        setIsProcessing(false);
      }
    };
    const handler = setTimeout(() => { processCrypto(); }, 500);
    return () => { clearTimeout(handler); };
  }, [inputText, secretKey, algorithm, mode, currentAlgorithm]);

  const handleCopy = () => {
    if (outputText && !error) {
      navigator.clipboard.writeText(outputText).then(() => {
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      });
    }
  };
  
  const handleAlgorithmChange = (newAlgo) => {
    setAlgorithm(newAlgo);
    const algoDef = allAlgos[newAlgo];
    if (algoDef.canDecrypt === false) {
        setMode('encrypt');
    }
  }

  return (
    <div className="bg-gray-900 text-gray-200 min-h-screen font-sans antialiased">
      <div className="absolute top-0 left-0 w-full h-full bg-gradient-to-br from-gray-900 via-indigo-900/40 to-black z-0"></div>
      <div className="relative z-10 flex min-h-screen">
          <Sidebar activeAlgorithm={algorithm} onAlgorithmChange={handleAlgorithmChange} />
          <Content
              algorithm={algorithm}
              mode={mode}
              setMode={setMode}
              inputText={inputText}
              setInputText={setInputText}
              secretKey={secretKey}
              setSecretKey={setSecretKey}
              outputText={outputText}
              error={error}
              isProcessing={isProcessing}
              handleCopy={handleCopy}
              copied={copied}
          />
      </div>
    </div>
  );
}
