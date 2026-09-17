"""Portuguese (pt-BR) renderings of the model vocabulary.

Only presentation strings are translated: asset names, control names, scenario
names and table/figure captions. MITRE ATT&CK technique names keep their
canonical English form, as is standard practice in Portuguese-language security
literature, and IEC 62443 / NIST CSF identifiers are language-neutral.
"""

from __future__ import annotations

from typing import Dict

ASSETS_PT: Dict[str, str] = {
    "ext_actor": "Ator externo",
    "sup_tier1": "TI do fornecedor Tier-1",
    "sup_edi": "Interface EDI/JIT de pedidos e logística",
    "sup_vendor_ra": "Acesso remoto do integrador",
    "sup_sw_update": "Canal de atualização de software e firmware OT",
    "sup_usb": "Mídia removível e arquivos de projeto",
    "saas_crm": "CRM/plataforma de clientes de terceiros",
    "saas_dms": "Plataforma de gestão de concessionárias",
    "it_email": "Serviço de e-mail corporativo",
    "it_user_ws": "Estação de trabalho do funcionário",
    "it_helpdesk": "Processo de service desk",
    "it_insider": "Insider recrutado ou coagido",
    "it_vpn": "Gateway de VPN de acesso remoto",
    "it_edge_app": "Aplicação corporativa exposta à Internet",
    "it_erp": "ERP e planejamento de produção",
    "it_fileshare": "Compartilhamentos de arquivos",
    "it_sccm": "Gestão de endpoints e distribuição de software",
    "it_backup": "Infraestrutura de backup",
    "id_user_cred": "Credenciais de usuário comum",
    "id_legacy_cred": "Credenciais dormentes de terceiros",
    "id_ad": "Active Directory local (tier 0)",
    "id_entra": "Provedor de identidade em nuvem",
    "id_federation": "Confiança de federação e SSO",
    "id_pam": "Gestão de acesso privilegiado",
    "cld_tenant": "Plano de controle do tenant de nuvem",
    "cld_storage": "Armazenamento de objetos e data lake",
    "cld_cicd": "Pipeline CI/CD e registro de artefatos",
    "cld_cv_backend": "Backend de veículo conectado",
    "dmz_jump": "Servidor de salto OT",
    "dmz_broker": "Broker de acesso remoto de fornecedores",
    "dmz_relay": "Relay de patches e antivírus",
    "dmz_mirror": "Espelho do historiador",
    "ops_mes": "Sistema de execução da manufatura (MES)",
    "ops_historian": "Historiador de processo",
    "ops_ews": "Estação de engenharia",
    "ops_ot_ad": "Controlador de domínio OT",
    "sca_server": "Servidor SCADA e de controle de linha",
    "sca_hmi": "Painel IHM do operador",
    "ctl_plc_body": "CLP da funilaria e linha de solda",
    "ctl_robot": "Controlador da célula robótica",
    "ctl_safety": "CLP de segurança",
    "prc_line": "Linha de montagem e solda",
    "prc_paint": "Pintura",
    "imp_prod_stop": "Parada de produção",
    "imp_quality": "Degradação silenciosa de qualidade",
    "imp_safety": "Perda de função de segurança",
    "imp_ip": "Roubo de dados de engenharia",
    "imp_pii": "Vazamento de dados pessoais",
}

CONTROLS_PT: Dict[str, str] = {
    "C01": "MFA resistente a phishing para acesso remoto e privilegiado",
    "C02": "Acesso condicional e conformidade de dispositivo",
    "C03": "Camadas administrativas e estações de acesso privilegiado",
    "C04": "Acesso remoto de fornecedores intermediado e just-in-time",
    "C05": "Segmentação TI/OT com DMZ industrial",
    "C06": "Lista de permissão de aplicações e controle de mídia em hosts OT",
    "C07": "Detecção em endpoint com resposta monitorada 24/7",
    "C08": "Backups imutáveis, offline e testados (TI e OT)",
    "C09": "Controle de mudança e integridade de programa em controladores",
    "C10": "Gestão de superfície de ataque e correção acelerada de serviços expostos",
    "C11": "Governança de SaaS e de tokens OAuth",
    "C12": "Higiene de identidades e revogação de credenciais dormentes",
    "C13": "Monitoramento contínuo de rede OT e inventário de ativos",
    "C14": "Garantia de segurança de fornecedores e telemetria contratual",
    "C15": "Verificação de identidade no service desk e risco de insider",
    "C16": "Gestão de postura de nuvem e de exposição de dados",
    "C17": "Resiliência operacional: buffers, fallback manual e modo degradado",
}

SCENARIOS_PT: Dict[str, str] = {
    "S0": "S0 linha de base",
    "S1": "S1 identidade primeiro",
    "S2": "S2 zonas e conduits IEC 62443",
    "S3": "S3 cadeia de fornecimento e nuvem",
    "S4": "S4 detectar e recuperar",
    "S5": "S5 programa completo",
}

CONFIDENCE_PT: Dict[str, str] = {
    "high": "alta", "medium": "média", "low": "baixa",
    "disputed": "disputada", "attempted": "tentativa", "partial": "parcial",
}

IMPACT_SHORT_PT: Dict[str, str] = {
    "prod_stop": "parada", "quality": "qualidade", "safety": "segurança",
    "ip": "eng.", "pii": "dados pessoais",
}

PROFILES_PT: Dict[str, str] = {
    "ransomware": "ransomware", "espionage": "espionagem", "sabotage": "sabotagem",
}

PLANES_PT: Dict[str, str] = {
    "it": "TI", "identity": "identidade", "cloud": "nuvem", "ot": "OT",
    "supply_chain": "cadeia de fornec.",
}


def asset(name_id: str, lang: str, fallback: str = "") -> str:
    if lang == "pt":
        return ASSETS_PT.get(name_id, fallback or name_id)
    return fallback or name_id


def control(cid: str, lang: str, fallback: str = "") -> str:
    if lang == "pt":
        return CONTROLS_PT.get(cid, fallback or cid)
    return fallback or cid
