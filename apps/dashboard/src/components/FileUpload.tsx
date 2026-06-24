import { useCallback, useState, useRef } from "react";

interface Props {
  onFile: (file: File) => void;
  disabled?: boolean;
}

export default function FileUpload({ onFile, disabled }: Props) {
  const [dragOver, setDragOver] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragOver(false);
      const file = e.dataTransfer.files[0];
      if (file && file.name.endsWith(".eml")) onFile(file);
    },
    [onFile]
  );

  const handleChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (file) onFile(file);
    },
    [onFile]
  );

  return (
    <div
      className={`file-upload ${dragOver ? "drag-over" : ""}`}
      onDragOver={(e) => {
        e.preventDefault();
        setDragOver(true);
      }}
      onDragLeave={() => setDragOver(false)}
      onDrop={handleDrop}
      onClick={() => inputRef.current?.click()}
    >
      <input
        ref={inputRef}
        type="file"
        accept=".eml"
        onChange={handleChange}
        disabled={disabled}
        hidden
      />
      <div className="file-upload-content">
        <div className="file-upload-icon">+</div>
        <p>Drop an .eml file here or click to browse</p>
        <span className="file-upload-hint">Max 10 MB</span>
      </div>
    </div>
  );
}
