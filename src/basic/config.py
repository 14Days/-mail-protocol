import pathlib
import threading
import yaml


class Config:
    _config = None
    _instance_lock = threading.Lock()

    @classmethod
    def get_instance(cls):
        if cls._config is None:
            with cls._instance_lock:
                path = pathlib.Path(__file__).parent.parent.parent
                path = pathlib.Path.joinpath(path, 'config.yaml')

                with open(str(path), 'rb') as f:
                    config = yaml.safe_load(f.read())
                    cls._config = config

        return cls._config
