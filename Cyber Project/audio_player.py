import sounddevice as sd
import soundfile as sf

class Audio_player:
    def __init__(self):
        self.stream = None

    def Play_Audio_By_File(self, filename):
        data, sr = sf.read(filename, dtype='float32')
        self.stream = sd.play(data, sr)
        
    def stop(self):
        sd.stop()
