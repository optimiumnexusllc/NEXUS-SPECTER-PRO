"""NEXUS SPECTER PRO — AES-256 Encryption | by OPTIMIUM NEXUS LLC"""
import os, base64
from cryptography.fernet import Fernet

def generate_key() -> bytes:
    return Fernet.generate_key()

def encrypt(data: str, key: bytes) -> str:
    return Fernet(key).encrypt(data.encode()).decode()

def decrypt(token: str, key: bytes) -> str:
    return Fernet(key).decrypt(token.encode()).decode()
