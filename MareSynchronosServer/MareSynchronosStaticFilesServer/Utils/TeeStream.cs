namespace MareSynchronosStaticFilesServer.Utils;

// Writes data read from one stream out to a second stream
public class TeeStream : Stream
{
    private readonly Stream _inStream;
    private readonly Stream _outStream;
    public bool DisposeUnderlying = true;

    public Stream InStream { get => _inStream; }
    public Stream OutStream { get => _outStream; }

    public TeeStream(Stream inStream, Stream outStream)
    {
        _inStream = inStream;
        _outStream = outStream;
    }

    protected override void Dispose(bool disposing)
    {
        if (!DisposeUnderlying)
            return;
        _inStream.Dispose();
        _outStream.Dispose();
    }

    public override bool CanRead => _inStream.CanRead;
    public override bool CanSeek => _inStream.CanSeek;
    public override bool CanWrite => false;
    public override long Length => _inStream.Length;

    public override long Position
    {
        get => _inStream.Position;
        set => _inStream.Position = value;
    }

    public override void Flush()
    {
        _inStream.Flush();
        _outStream.Flush();
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        int n = _inStream.Read(buffer, offset, count);
        if (n > 0)
            _outStream.Write(buffer, offset, n);
        return n;
    }

    public async override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        int n = await _inStream.ReadAsync(buffer, offset, count, cancellationToken);
        if (n > 0)
            await _outStream.WriteAsync(buffer, offset, n);
        return n;
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        return _inStream.Seek(offset, origin);
    }

    public override void SetLength(long value)
    {
        _inStream.SetLength(value);
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        throw new NotSupportedException();
    }
}
