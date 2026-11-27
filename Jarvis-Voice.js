
(() => {
  const synth = window.speechSynthesis;

  function speak(text) {
    if (!synth || !text) return;

    synth.cancel();

    const voice = new SpeechSynthesisUtterance(text);
    const voices = synth.getVoices();

    voice.lang = "ar-SA";
    voice.rate = 0.92;
    voice.pitch = 0.88;
    voice.volume = 1;

    const arabicVoice = voices.find(v => v.lang.toLowerCase().startsWith("ar"));
    if (arabicVoice) {
      voice.voice = arabicVoice;
      voice.lang = arabicVoice.lang;
    }

    voice.onstart = () => {
      document.documentElement.classList.add("jarvis-speaking");
    };

    voice.onend = () => {
      document.documentElement.classList.remove("jarvis-speaking");
    };

    synth.speak(voice);
  }

  function stop() {
    if (synth) synth.cancel();
    document.documentElement.classList.remove("jarvis-speaking");
  }

  window.JarvisVoice = { speak, stop };
})();
