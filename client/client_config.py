from dataclasses import dataclass

@dataclass
class ClientConfig:
    server_host: str = "192.168.0.103"
    server_port: int = 9000
    timeout_sec: int = 10
    sim_config_path: str = "sim.json"