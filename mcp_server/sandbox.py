def validate_block_rule(ip_address: str, reason: str) -> str:
    if not ip_address.startswith("192.168.") and not ip_address.startswith("10."):
        return f"[SANDBOX REJECT] IP {ip_address} fora do escopo de borda permitido."
    
    rule = f"ovs-ofctl add-flow br0 priority=100,ip,nw_src={ip_address},actions=drop"
    return f"[SANDBOX APPROVE] Regra gerada: {rule} | Motivo: {reason}"