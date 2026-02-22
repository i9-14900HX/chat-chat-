"""
import sounddevice as sd
import soundfile as sf

class Audio_player:
    def __init__(self):
        self.stream = None

    def Play_Audio_By_File(self, filename):
        self.stop()  # Stop any currently playing audio
        data, sr = sf.read(filename, dtype='float32')
        self.stream = sd.play(data, sr)
        
    def stop(self):
        sd.stop()
"""
import sounddevice as sd
import soundfile as sf
import threading

class Audio_player:
    def __init__(self):
        self.lock = threading.Lock()  # מונע race בין play/stop

    def Play_Audio_By_File(self, filename):
        #ליוסיף בדיקה אם קיים הקוב.ץ 
        """נגן קובץ שמע; אם יש נגינה קיימת, עוצר ומתחיל מחדש"""
        with self.lock:
            sd.stop()  # עוצר כל נגינה קודמת
            data, sr = sf.read(filename, dtype='float32')
            sd.play(data, sr)  # מתחיל נגינה

    def stop(self):
        """עצר את הנגינה הנוכחית"""
        with self.lock:
            sd.stop()