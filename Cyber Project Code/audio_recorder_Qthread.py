from PyQt6.QtCore import QObject, pyqtSignal, QThread
import sounddevice as sd
import numpy as np
import time

# אנחנו הופכים את ה-Recorder ל-QObject כדי שיוכל לשלוח סיגנלים
class Recorder(QObject):
    # סיגנל שישלח את ה-bytes בסיום
    finished_recording = pyqtSignal(bytes)

    def callback(self, indata, frames, time, status):
        if status:
            print(f"Warning: {status}")
        self.recorded_frames.append(indata.copy())

    def Start_Recording(self):
        
        self.running = True
        self.recorded_frames = []
        self.stream = sd.InputStream(callback=self.callback, samplerate=44100, channels=1) 
        self.stream.start()   
        self.is_force_close = True
        while self.running:
            time.sleep(0.01)
            
        # לוגיקת הסיום (בתוך ה-Thread)
        time.sleep(0.3) 
        self.stream.stop()
        self.stream.close()
        self.is_force_close = False

        self.full_audio_stream_numpy = np.concatenate(self.recorded_frames)
        audio_bytes = self.full_audio_stream_numpy.tobytes()
        
        # כאן קורה הקסם: שליחת המידע ל-GUI

        self.finished_recording.emit(audio_bytes)

    def End_Recording(self):
        self.running = False

    def Force_close(self):
        if self.is_force_close:
            print("forcing stream to stop")
            self.stream.stop()
            self.stream.close()
            self.is_force_close = False

    def __del__(self):
    # שימוש ב-getattr כדי למנוע קריסה אם המשתנה לא קיים
        stream = getattr(self, 'stream', None)
        if stream is not None:
            try:
                stream.stop()
                stream.close()
            except:
                pass