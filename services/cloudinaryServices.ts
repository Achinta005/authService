import { v2 as Cloudinary } from "cloudinary";

export class CloudinaryService {
  private cloudinary: typeof Cloudinary;

  constructor() {
    this.cloudinary = Cloudinary;
    this.configure();
  }

  private configure() {
    this.cloudinary.config({
      cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
      api_key: process.env.CLOUDINARY_API_KEY,
      api_secret: process.env.CLOUDINARY_API_SECRET,
    });
  }

  async delete(publicId: string) {
    return this.cloudinary.uploader.destroy(publicId, {
      resource_type: "image",
    });
  }

  async uploadBuffer(buffer: Buffer, username: string): Promise<any> {
    return new Promise((resolve, reject) => {
      const publicId = `${username}_${Date.now()}`;

      this.cloudinary.uploader
        .upload_stream(
          {
            folder: "devcollab/profile_pictures",
            public_id: publicId,
            resource_type: "image",
            transformation: [
              {
                width: 400,
                height: 400,
                crop: "fill",
                gravity: "face",
                quality: "auto:good",
              },
            ],
          },
          (error, result) => {
            if (error) return reject(error);
            resolve(result);
          },
        )
        .end(buffer);
    });
  }

  getOptimizedUrl(publicId: string, options = {}) {
    return this.cloudinary.url(publicId, {
      width: 400,
      height: 400,
      crop: "fill",
      gravity: "face",
      quality: "auto:good",
      fetch_format: "auto",
      ...options,
    });
  }

  async getImageInfo(publicId: string) {
    try {
      const result = await this.cloudinary.api.resource(publicId);
      return {
        public_id: result.public_id,
        format: result.format,
        width: result.width,
        height: result.height,
        bytes: result.bytes,
        created_at: result.created_at,
        secure_url: result.secure_url,
      };
    } catch {
      return null;
    }
  }

  async testConnection() {
    try {
      await this.cloudinary.api.ping();
      console.log("✅ Cloudinary connected successfully");
      return true;
    } catch (error: any) {
      console.error("❌ Cloudinary connection failed:", error.message);
      return false;
    }
  }
}
