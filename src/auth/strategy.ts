import {AuthenticationStrategy} from '@loopback/authentication';
import {AuthenticationBindings} from '@loopback/authentication/dist/keys';
import {AuthenticationMetadata} from '@loopback/authentication/dist/types';
import {inject} from '@loopback/context';
import {HttpErrors, Request} from '@loopback/rest';
import {UserProfile} from '@loopback/security';
import parseBearerToken from 'parse-bearer-token';
import {ConfiguracionSeguridad} from '../config/configuracion.seguridad';
const fecht = require('node-fetch');

export class AuthStrategy implements AuthenticationStrategy {
  name: string = 'auth';

  constructor(
    @inject(AuthenticationBindings.METADATA)
    private metadata: AuthenticationMetadata[]
  ) { }
  /**
   * Autenticacion de un usuario frente a una accion en la base de datos
   * @param request la solicitud con el token
   * @returns el perfil del usuario, underfined cuando no tiene un permiso o un HTTPError
   */
  async authenticate(request: Request): Promise<UserProfile | undefined> {
    let token = parseBearerToken(request);
    if (token) {
      let idMenu: string = this.metadata[0].options![0];
      let accion: string = this.metadata[0].options![1];
      console.log(this.metadata);

      const datos = {token: token, idMenu: idMenu, accion: accion}
      const urlValidarPermisos = `${ConfiguracionSeguridad.enlaceMicroserivicioSeguridad}/validad-permisos`
      let res = undefined;
      try {
        await fecht(urlValidarPermisos, {
          method: 'post',
          body: JSON.stringify(datos),
          headers: {'Content-type': 'application/json', 'Authorization': `Bearer${token}`},
        })
          .then((res: any) => res.json())
          .then((json: any) => {
            res = json;
          });
        if (res) {
          let perfil: UserProfile = Object.assign({
            permitido: "OK"
          });
          return perfil;
        } else {
          return undefined;
        }
      }
      catch (e) {
        throw new HttpErrors[401]("No se tienen permisos sobre la accion a ejecutar.");
      }
    }
    throw new HttpErrors[401]("No es posible ejecutar la accion por falta de un token.");
  }
}
